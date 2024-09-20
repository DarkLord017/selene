package consensus

///NOTE: only these imports are required others are in package already
// uses rpc
// uses config for networks
// uses common for datatypes
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"

	"os"
	"sync"
	"time"

	"github.com/BlocSoc-iitr/selene/common"
	"github.com/BlocSoc-iitr/selene/config"
	"github.com/BlocSoc-iitr/selene/config/checkpoints"
	"github.com/BlocSoc-iitr/selene/consensus/consensus_core"
	"github.com/BlocSoc-iitr/selene/consensus/rpc"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
)

var (
	ErrIncorrectRpcNetwork           = errors.New("incorrect RPC network")
	ErrPayloadNotFound               = errors.New("payload not found")
	ErrInvalidHeaderHash             = errors.New("invalid header hash")
	ErrCheckpointTooOld              = errors.New("checkpoint too old")
	ErrBootstrapFetchFailed          = errors.New("could not fetch bootstrap")
	ErrInvalidUpdate                 = errors.New("invalid update")
	ErrInsufficientParticipation     = errors.New("insufficient participation")
	ErrInvalidTimestamp              = errors.New("invalid timestamp")
	ErrInvalidPeriod                 = errors.New("invalid period")
	ErrNotRelevant                   = errors.New("update not relevant")
	ErrInvalidFinalityProof          = errors.New("invalid finality proof")
	ErrInvalidNextSyncCommitteeProof = errors.New("invalid next sync committee proof")
	ErrInvalidSignature              = errors.New("invalid signature")
)

const MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128

type GenericUpdate struct {
	AttestedHeader          consensus_core.Header
	SyncAggregate           consensus_core.SyncAggregate
	SignatureSlot           uint64
	NextSyncCommittee       *consensus_core.SyncComittee
	NextSyncCommitteeBranch *[]consensus_core.Bytes32
	FinalizedHeader         consensus_core.Header
	FinalityBranch          []consensus_core.Bytes32
}

type ConsensusClient struct {
	BlockRecv          *common.Block
	FinalizedBlockRecv *common.Block
	CheckpointRecv     *[]byte
	genesisTime        uint64
	db                 Database
}

type Inner struct {
	RPC                rpc.ConsensusRpc
	Store              LightClientStore
	lastCheckpoint     *[]byte
	blockSend          chan common.Block
	finalizedBlockSend chan *common.Block
	checkpointSend     chan *[]byte
	Config             *config.Config
}
type LightClientStore struct {
	FinalizedHeader               consensus_core.Header
	CurrentSyncCommitee           consensus_core.SyncComittee
	NextSyncCommitee              *consensus_core.SyncComittee
	OptimisticHeader              consensus_core.Header
	PreviousMaxActiveParticipants uint64
	CurrentMaxActiveParticipants  uint64
}

type Forks struct {
	Genesis   Fork
	Altair    Fork
	Bellatrix Fork
	Capella   Fork
	Deneb     Fork
}

type Fork struct {
	Version uint64
	Epoch   uint64
}

func (con ConsensusClient) New(rpc *string, config config.Config) ConsensusClient {
	blockSend := make(chan common.Block, 256)
	finalizedBlockSend := make(chan *common.Block)
	checkpointSend := make(chan *[]byte)

	db, err := con.db.New(&config)
	if err != nil {
		panic(err)
	}

	initialCheckpoint := config.Checkpoint || db.load_checkpoint()
	if initialCheckpoint == nil {
		panic("No checkpoint found")
	}
	In := &Inner{}
	inner := In.New(*rpc, blockSend, finalizedBlockSend, checkpointSend, &config)

	go func() {
		err := inner.sync(initialCheckpoint)
		if err != nil {
			if inner.Config.LoadExternalFallback {
				err = sync_all_fallback(inner, inner.Config.Chain.ChainID)
				if err != nil {
					log.Printf("sync failed: %v", err)
					os.Exit(1)
				}
			} else if inner.Config.Fallback != nil {
				err = sync_fallback(inner, inner.Config.Fallback)
				if err != nil {
					log.Printf("sync failed: %v", err)
					os.Exit(1)
				}
			} else {
				log.Printf("sync failed: %v", err)
				os.Exit(1)
			}
		}

		_ = inner.send_blocks()

		for {
			time.Sleep(inner.duration_until_next_update())

			err := inner.advance()
			if err != nil {
				log.Printf("advance error: %v", err)
				continue
			}

			err = inner.send_blocks()
			if err != nil {
				log.Printf("send error: %v", err)
				continue
			}
		}
	}()

	blocksReceived := <-blockSend
	finalizedBlocksReceived := <-finalizedBlockSend
	checkpointsReceived := <-checkpointSend

	return ConsensusClient{
		BlockRecv:          &blocksReceived,
		FinalizedBlockRecv: finalizedBlocksReceived,
		CheckpointRecv:     checkpointsReceived,
		genesisTime:        config.Chain.GenesisTime,
		db:                 db,
	}

}
func (con ConsensusClient) Shutdown() error {
	checkpoint := con.CheckpointRecv
	if checkpoint != nil {
		err := con.db.SaveCheckpoint(*checkpoint)
		if err != nil {
			return err
		}
	}
	return nil
}
func (con ConsensusClient) expected_current_slot() uint64 {
	now := time.Now().Unix()
	// Assuming SLOT_DURATION is the duration of each slot in seconds
	const SLOT_DURATION uint64 = 12
	return (uint64(now) - con.genesisTime) / SLOT_DURATION
}

func sync_fallback(inner *Inner, fallback *string) error {
	cf, err := (&checkpoints.CheckpointFallback{}).Fetch_latest_checkpoint_from_api(*fallback)
	if err != nil {
		return errors.Wrap(err, "failed to fetch checkpoint from API")
	}
	return inner.sync(cf)

}
func sync_all_fallback(inner *Inner, chainID uint64) error {
	var n config.Network
	network, err := n.ChainID(chainID)

	ch := checkpoints.CheckpointFallback{}

	checkpointFallback, err := ch.Build()
	if err != nil {
		return err
	}

	// Fetch the latest checkpoint from the network
	checkpoint := checkpointFallback.Fetch_latest_checkpoint(network)
	if err != nil {
		return err
	}

	// Sync using the inner struct's sync method
	if err := inner.sync(checkpoint); err != nil {
		return err
	}

	return nil
}

func (in *Inner) New(rpcURL string, blockSend chan common.Block, finalizedBlockSend chan *common.Block, checkpointSend chan *[]byte, config *config.Config) *Inner {
	rpcClient := rpc.NewConsensusRpc(rpcURL)

	return &Inner{
		RPC:                rpcClient,
		Store:              LightClientStore{},
		lastCheckpoint:     nil, // No checkpoint initially
		blockSend:          blockSend,
		finalizedBlockSend: finalizedBlockSend,
		checkpointSend:     checkpointSend,
		Config:             config,
	}

}
func (in *Inner) Get_rpc() error {
	chainID, err := in.RPC.ChainId()
	if err != nil {
		return err
	}
	if chainID != in.Config.Chain.ChainID {
		return ErrIncorrectRpcNetwork
	}
	return nil
}
func (in *Inner) check_execution_payload(ctx context.Context, slot *uint64) (*consensus_core.ExecutionPayload, error) {
	if slot == nil {
		slot = &in.Store.OptimisticHeader.Slot
	}

	block, err := in.RPC.GetBlock(*slot)
	if err != nil {
		return nil, err
	}

	blockHash := block.Body.TreeHashRoot()

	latestSlot := in.Store.OptimisticHeader.Slot
	finalizedSlot := in.Store.FinalizedHeader.Slot

	var verifiedBlockHash interface{}
	if *slot == latestSlot {
		verifiedBlockHash = in.Store.OptimisticHeader.TreeHashRoot()
	} else if *slot == finalizedSlot {
		verifiedBlockHash = in.Store.FinalizedHeader.TreeHashRoot()
	} else {
		return nil, ErrPayloadNotFound
	}

	if verifiedBlockHash != blockHash {
		return nil, fmt.Errorf("%w: expected %v but got %v", ErrInvalidHeaderHash, verifiedBlockHash, blockHash)
	}

	payload := block.Body.Execution_payload
	return &payload, nil
}
func (in *Inner) get_payloads(ctx context.Context, startSlot, endSlot uint64) ([]interface{}, error) {
	var payloads []interface{}

	// Fetch the block at endSlot to get the initial parent hash
	endBlock, err := in.RPC.GetBlock(endSlot)
	if err != nil {
		return nil, err
	}
	endPayload := endBlock.Body.Execution_payload
	prevParentHash := endPayload.Parent_hash

	// Create a wait group to manage concurrent fetching
	var wg sync.WaitGroup
	payloadsChan := make(chan interface{}, endSlot-startSlot+1)
	errorChan := make(chan error, 1) // Buffer for one error

	// Fetch blocks in parallel
	for slot := endSlot; slot >= startSlot; slot-- {
		wg.Add(1)
		go func(slot uint64) {
			defer wg.Done()
			block, err := in.RPC.GetBlock(slot)
			if err != nil {
				errorChan <- err
				return
			}
			payload := block.Body.Execution_payload
			if payload.Parent_hash != prevParentHash {
				log.Printf("Error while backfilling blocks: expected block hash %v but got %v", prevParentHash, payload.BlockHash())
				return
			}
			prevParentHash = *&payload.Parent_hash
			payloadsChan <- *&payload
		}(slot)
	}

	// Close channels after all fetches are complete
	go func() {
		wg.Wait()
		close(payloadsChan)
		close(errorChan)
	}()

	// Collect results and check for errors
	for {
		select {
		case payload, ok := <-payloadsChan:
			if !ok {
				return payloads, nil
			}
			payloads = append(payloads, payload)
		case err := <-errorChan:
			return nil, err
		}
	}
}
func (in *Inner) advance() error {
	// Fetch and apply finality update
	finalityUpdate, err := in.RPC.GetFinalityUpdate()
	if err != nil {
		return err
	}
	if err := in.verify_finality_update(&finalityUpdate); err != nil {
		return err
	}
	in.apply_finality_update(&finalityUpdate)

	// Fetch and apply optimistic update
	optimisticUpdate, err := in.RPC.GetOptimisticUpdate()
	if err != nil {
		return err
	}
	if err := in.verify_optimistic_update(&optimisticUpdate); err != nil {
		return err
	}
	in.apply_optimistic_update(&optimisticUpdate)

	// Check for sync committee update if it's not set
	if in.Store.NextSyncCommitee == nil {
		log.Printf("checking for sync committee update")

		currentPeriod := calculate_sync_period(in.Store.FinalizedHeader.Slot)
		updates, err := in.RPC.GetUpdates(currentPeriod, 1)
		if err != nil {
			return err
		}

		if len(updates) == 1 {
			update := updates[0]
			if err := in.verify_update(&update); err == nil {
				log.Printf("updating sync committee")
				in.apply_update(&update)
			}
		}
	}

	return nil
}
func (in *Inner) sync(checkpoint [32]byte) error {
	// Reset store and checkpoint
	in.Store = LightClientStore{}
	in.lastCheckpoint = nil

	// Perform bootstrap with the given checkpoint
	in.bootstrap(checkpoint)

	// Calculate the current sync period
	currentPeriod := calculate_sync_period(in.Store.FinalizedHeader.Slot)

	// Fetch updates
	updates, err := in.RPC.GetUpdates(currentPeriod, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
	if err != nil {
		return err
	}

	// Apply updates
	for _, update := range updates {
		if err := in.verify_update(&update); err != nil {
			return err
		}
		in.apply_update(&update)
	}

	// Fetch and apply finality update
	finalityUpdate, err := in.RPC.GetFinalityUpdate()
	if err != nil {
		return err
	}
	if err := in.verify_finality_update(&finalityUpdate); err != nil {
		return err
	}
	in.apply_finality_update(&finalityUpdate)

	// Fetch and apply optimistic update
	optimisticUpdate, err := in.RPC.GetOptimisticUpdate()
	if err != nil {
		return err
	}
	if err := in.verify_optimistic_update(&optimisticUpdate); err != nil {
		return err
	}
	in.apply_optimistic_update(&optimisticUpdate)

	// Log the success message
	log.Printf("consensus client in sync with checkpoint: 0x%s", hex.EncodeToString(checkpoint[:]))

	return nil
}
func (in *Inner) send_blocks() error {
	// Get slot from the optimistic header
	slot := in.Store.OptimisticHeader.Slot
	payload, err := in.check_execution_payload(context.Background(), &slot)
	if err != nil {
		return err
	}

	// Get finalized slot from the finalized header
	finalizedSlot := in.Store.FinalizedHeader.Slot
	finalizedPayload, err := in.check_execution_payload(context.Background(), &finalizedSlot)
	if err != nil {
		return err
	}

	// Send payload converted to block over the BlockSend channel
	go func() {
		in.blockSend <- PayloadToBlock(*payload)
	}()

	// Send finalized payload converted to block over the FinalizedBlockSend channel
	go func() {
		in.finalizedBlockSend <- &PayloadToBlock(*finalizedPayload)
	}()

	// Send checkpoint over the CheckpointSend channel
	go func() {
		in.checkpointSend <- in.lastCheckpoint
	}()

	return nil
}

func (in *Inner) duration_until_next_update() time.Duration {
	currentSlot := in.expected_current_slot()
	nextSlot := currentSlot + 1
	nextSlotTimestamp := nextSlot*12 + in.Config.Chain.GenesisTime

	now := uint64(time.Now().Unix())
	timeToNextSlot := int64(nextSlotTimestamp - now)
	nextUpdate := timeToNextSlot + 4

	return time.Duration(nextUpdate) * time.Second
}
func (in *Inner) bootstrap(checkpoint [32]byte) {
	bootstrap, errInBootstrap := in.RPC.GetBootstrap(checkpoint)
	if errInBootstrap != nil {
		log.Printf("failed to fetch bootstrap: %v", errInBootstrap)
		return
	}

	isValid := in.is_valid_checkpoint(bootstrap.Header.Slot)
	if !isValid {
		if in.Config.StrictCheckpointAge == true {
			log.Printf("checkpoint too old, consider using a more recent checkpoint")
			return
		} else {
			log.Printf("checkpoint too old, consider using a more recent checkpoint")
		}
	}

	verify_bootstrap(checkpoint, bootstrap)
	apply_bootstrap(&in.Store, bootstrap)

}
func verify_bootstrap(checkpoint [32]byte, bootstrap consensus_core.Bootstrap) {
	isCommitteValid := isCurrentCommitteeProofValid(&bootstrap.Header, &bootstrap.CurrentSyncCommittee, bootstrap.CurrentSyncCommitteeBranch)
	if !isCommitteValid {
		log.Println("invalid current sync committee proof")
		return
	}

	headerHash := bootstrap.Header.TreeHashRoot()
	HeaderValid := headerHash == checkpoint

	if !HeaderValid {
		log.Println("invalid header hash")
		return
	}

}

func apply_bootstrap(store *LightClientStore, bootstrap consensus_core.Bootstrap) {
	store.FinalizedHeader = bootstrap.Header
	store.CurrentSyncCommitee = bootstrap.CurrentSyncCommittee
	store.NextSyncCommitee = nil
	store.OptimisticHeader = bootstrap.Header
	store.PreviousMaxActiveParticipants = 0
	store.CurrentMaxActiveParticipants = 0

}

func (in *Inner) verify_generic_update(update *GenericUpdate, expectedCurrentSlot uint64, store *LightClientStore, genesisRoots []byte, forks consensus_rpc.Fork) error {
	{
		bits := getBits(update.SyncAggregate.Sync_committee_bits)
		if bits == 0 {
			return ErrInsufficientParticipation
		}

		updateFinalizedSlot := update.FinalizedHeader.Slot
		validTime := expectedCurrentSlot >= update.SignatureSlot &&
			update.SignatureSlot > update.AttestedHeader.Slot &&
			update.AttestedHeader.Slot >= updateFinalizedSlot

		if !validTime {
			return ErrInvalidTimestamp
		}

		storePeriod := calculate_sync_period(store.FinalizedHeader.Slot)
		updateSigPeriod := calculate_sync_period(update.SignatureSlot)

		var validPeriod bool
		if store.NextSyncCommitee != nil {
			validPeriod = updateSigPeriod == storePeriod || updateSigPeriod == storePeriod+1
		} else {
			validPeriod = updateSigPeriod == storePeriod
		}

		if !validPeriod {
			return ErrInvalidPeriod
		}

		updateAttestedPeriod := calculate_sync_period(update.AttestedHeader.Slot)
		updateHasNextCommittee := store.NextSyncCommitee == nil && &update.NextSyncCommittee != nil && updateAttestedPeriod == storePeriod

		if update.AttestedHeader.Slot <= store.FinalizedHeader.Slot && !updateHasNextCommittee {
			return ErrNotRelevant
		}

		if &update.FinalizedHeader != nil && update.FinalityBranch != nil {
			if !isFinalityProofValid(&update.AttestedHeader, &update.FinalizedHeader, update.FinalityBranch) {
				return ErrInvalidFinalityProof
			}
		} else if &update.FinalizedHeader != nil {
			return ErrInvalidFinalityProof
		}

		if &update.NextSyncCommittee != nil && update.NextSyncCommitteeBranch != nil {
			if !isNextCommitteeProofValid(&update.AttestedHeader, update.NextSyncCommittee, *update.NextSyncCommitteeBranch) {
				return ErrInvalidNextSyncCommitteeProof
			}
		} else if &update.NextSyncCommittee != nil {
			return ErrInvalidNextSyncCommitteeProof
		}

		var syncCommittee *consensus_core.SyncComittee
		if updateSigPeriod == storePeriod {
			syncCommittee = &in.Store.CurrentSyncCommitee
		} else {
			syncCommittee = in.Store.NextSyncCommitee
		}

		pks, err := consensus_core.GetParticipatingKeys(syncCommittee, update.SyncAggregate.Sync_committee_bits)
		if err != nil {
			return fmt.Errorf("failed to get participating keys: %w", err)
		}

		forkVersion := consensus_core.CalculateForkVersion(forks, update.SignatureSlot)
		forkDataRoot := consensus_core.ComputeForkDataRoot(forkVersion, consensus_core.Bytes32(in.Config.Chain.GenesisRoot))

		if !verify_sync_committee_signature(pks, &update.AttestedHeader, &update.SyncAggregate.Sync_committee_signature, forkDataRoot) {
			return ErrInvalidSignature
		}

		return nil
	}
}
func (in *Inner) verify_update(update *consensus_core.Update) error {
	genUpdate := GenericUpdate{
		AttestedHeader:          update.AttestedHeader,
		SyncAggregate:           update.SyncAggregate,
		SignatureSlot:           update.SignatureSlot,
		NextSyncCommittee:       &update.NextSyncCommitee,
		NextSyncCommitteeBranch: &update.NextSyncCommiteeBranch,
		FinalizedHeader:         update.FinalizedHeader,
		FinalityBranch:          update.FinalityBranch,
	}
	return in.verify_generic_update(&genUpdate, in.expected_current_slot(), &in.Store, in.Config.Chain.GenesisRoot, in.Config.Forks)
}
func (in *Inner) verify_finality_update(update *consensus_core.FinalityUpdate) error {
	genUpdate := GenericUpdate{
		AttestedHeader:  update.AttestedHeader,
		SyncAggregate:   update.SyncAggregate,
		SignatureSlot:   update.SignatureSlot,
		FinalizedHeader: update.FinalizedHeader,
		FinalityBranch:  update.FinalityBranch,
	}
	return in.verify_generic_update(&genUpdate, in.expected_current_slot(), &in.Store, in.Config.Chain.GenesisRoot, in.Config.Forks)
}
func (in *Inner) verify_optimistic_update(update *consensus_core.OptimisticUpdate) error {
	genUpdate := GenericUpdate{
		AttestedHeader: update.AttestedHeader,
		SyncAggregate:  update.SyncAggregate,
		SignatureSlot:  update.SignatureSlot,
	}
	return in.verify_generic_update(&genUpdate, in.expected_current_slot(), &in.Store, in.Config.Chain.GenesisRoot, in.Config.Forks)
}
func (in *Inner) apply_generic_update(store *LightClientStore, update *GenericUpdate) *[]byte {
	committeeBits := getBits(update.SyncAggregate.Sync_committee_bits)

	// Update max active participants
	if committeeBits > store.CurrentMaxActiveParticipants {
		store.CurrentMaxActiveParticipants = committeeBits
	}

	// Determine if we should update the optimistic header
	shouldUpdateOptimistic := committeeBits > in.safety_threshold() &&
		update.AttestedHeader.Slot > store.OptimisticHeader.Slot

	if shouldUpdateOptimistic {
		store.OptimisticHeader = update.AttestedHeader
	}

	updateAttestedPeriod := calculate_sync_period(update.AttestedHeader.Slot)

	updateFinalizedSlot := uint64(0)
	if &update.FinalizedHeader != nil {
		updateFinalizedSlot = update.FinalizedHeader.Slot
	}
	updateFinalizedPeriod := calculate_sync_period(updateFinalizedSlot)

	updateHasFinalizedNextCommittee := in.Store.NextSyncCommitee == nil &&
		in.has_sync_update(update) && in.has_finality_update(update) &&
		updateFinalizedPeriod == updateAttestedPeriod

	// Determine if we should apply the update
	hasMajority := committeeBits*3 >= 512*2
	if !hasMajority {
		log.Println("skipping block with low vote count")
	}

	updateIsNewer := updateFinalizedSlot > store.FinalizedHeader.Slot
	goodUpdate := updateIsNewer || updateHasFinalizedNextCommittee

	shouldApplyUpdate := hasMajority && goodUpdate

	// Apply the update if conditions are met
	if shouldApplyUpdate {
		storePeriod := calculate_sync_period(store.FinalizedHeader.Slot)

		// Sync committee update logic
		if store.NextSyncCommitee == nil {
			store.NextSyncCommitee = update.NextSyncCommittee
		} else if updateFinalizedPeriod == storePeriod+1 {
			log.Println("sync committee updated")
			store.CurrentSyncCommitee = *store.NextSyncCommitee
			store.NextSyncCommitee = update.NextSyncCommittee
			store.PreviousMaxActiveParticipants = store.CurrentMaxActiveParticipants
			store.CurrentMaxActiveParticipants = 0
		}

		// Update finalized header
		if updateFinalizedSlot > store.FinalizedHeader.Slot {
			store.FinalizedHeader = update.FinalizedHeader

			if store.FinalizedHeader.Slot > store.OptimisticHeader.Slot {
				store.OptimisticHeader = store.FinalizedHeader
			}

			if store.FinalizedHeader.Slot%32 == 0 {
				checkpoint := store.FinalizedHeader.TreeHashRoot()
				return &checkpoint
			}
		}
	}

	return nil
}
func (in *Inner) apply_update(update *consensus_core.Update) {
	genUpdate := GenericUpdate{
		AttestedHeader:          update.AttestedHeader,
		SyncAggregate:           update.SyncAggregate,
		SignatureSlot:           update.SignatureSlot,
		NextSyncCommittee:       &update.NextSyncCommitee,
		NextSyncCommitteeBranch: &update.NextSyncCommiteeBranch,
		FinalizedHeader:         update.FinalizedHeader,
		FinalityBranch:          update.FinalityBranch,
	}
	checkpoint := in.apply_generic_update(&in.Store, &genUpdate)
	if checkpoint != nil {
		in.lastCheckpoint = checkpoint
	}
}
func (in *Inner) apply_finality_update(update *consensus_core.FinalityUpdate) {
	genUpdate := GenericUpdate{
		AttestedHeader:  update.AttestedHeader,
		SyncAggregate:   update.SyncAggregate,
		SignatureSlot:   update.SignatureSlot,
		FinalizedHeader: update.FinalizedHeader,
		FinalityBranch:  update.FinalityBranch,
	}
	checkpoint := in.apply_generic_update(&in.Store, &genUpdate)
	if checkpoint != nil {
		in.lastCheckpoint = checkpoint
	}
}
func (in *Inner) apply_optimistic_update(update *consensus_core.OptimisticUpdate) {
	genUpdate := GenericUpdate{
		AttestedHeader: update.AttestedHeader,
		SyncAggregate:  update.SyncAggregate,
		SignatureSlot:  update.SignatureSlot,
	}
	checkpoint := in.apply_generic_update(&in.Store, &genUpdate)
	if checkpoint != nil {
		in.lastCheckpoint = checkpoint
	}
}
func (in *Inner) log_finality_update(update *consensus_core.FinalityUpdate) {
	participation := float32(getBits(update.SyncAggregate.Sync_committee_bits)) / 512.0 * 100.0
	decimals := 2
	if participation == 100.0 {
		decimals = 1
	}

	age := in.age(in.Store.FinalizedHeader.Slot)
	days := age.Hours() / 24
	hours := int(age.Hours()) % 24
	minutes := int(age.Minutes()) % 60
	seconds := int(age.Seconds()) % 60

	log.Printf(
		"finalized slot             slot=%d  confidence=%.*f%%  age=%02d:%02d:%02d:%02d",
		in.Store.FinalizedHeader.Slot, decimals, participation, int(days), hours, minutes, seconds,
	)
}
func (in *Inner) log_optimistic_update(update *consensus_core.OptimisticUpdate) {
	participation := float32(getBits(update.SyncAggregate.Sync_committee_bits)) / 512.0 * 100.0
	decimals := 2
	if participation == 100.0 {
		decimals = 1
	}

	age := in.age(in.Store.OptimisticHeader.Slot)
	days := age.Hours() / 24
	hours := int(age.Hours()) % 24
	minutes := int(age.Minutes()) % 60
	seconds := int(age.Seconds()) % 60

	log.Printf(
		"updated head               slot=%d  confidence=%.*f%%  age=%02d:%02d:%02d:%02d",
		in.Store.OptimisticHeader.Slot, decimals, participation, int(days), hours, minutes, seconds,
	)
}
func (in *Inner) has_finality_update(update *GenericUpdate) bool {
	return &update.FinalizedHeader != nil && update.FinalityBranch != nil
}
func (in *Inner) has_sync_update(update *GenericUpdate) bool {
	return &update.NextSyncCommittee != nil && update.NextSyncCommitteeBranch != nil
}
func (in *Inner) safety_threshold() uint64 {
	return max(in.Store.CurrentMaxActiveParticipants, in.Store.PreviousMaxActiveParticipants) / 2
}
func verify_sync_committee_signature(pks []consensus_core.BLSPubKey, attestedHeader *consensus_core.Header, signature *consensus_core.SignatureBytes, forkDataRoot consensus_core.Bytes32) bool {
	headerRoot := attestedHeader.TreeHashRoot()
	signingRoot := consensus_core.ComputeCommitteeSignRoot(headerRoot, forkDataRoot)
	return signature.Verify(signingRoot[:], pks)
}
func (in *Inner) compute_committee_sign_root(header consensus_core.Bytes32, fork consensus_core.Bytes32) []byte {
	consensus_core.ComputeCommitteeSignRoot(header, fork)
}
func (in *Inner) age(slot uint64) time.Duration {
	expectedTime := slot*12 + in.Config.Chain.GenesisTime
	now := time.Now().Unix()
	return time.Duration(uint64(now)-expectedTime) * time.Second
}
func (in *Inner) expected_current_slot() uint64 {
	const SLOT_DURATION = 12

	now := time.Now().Unix()

	sinceGenesis := now - int64(in.Config.Chain.GenesisTime)
	return uint64(sinceGenesis) / SLOT_DURATION
}
func (in *Inner) is_valid_checkpoint(blockHashSlot uint64) bool {
	const SLOT_DURATION = 12
	currentSlot := in.expected_current_slot()
	currentSlotTimestamp := int64(in.Config.Chain.GenesisTime) + int64(currentSlot)*SLOT_DURATION
	blockhashSlotTimestamp := int64(in.Config.Chain.GenesisTime) + int64(blockHashSlot)*SLOT_DURATION

	slotAge := currentSlotTimestamp - blockhashSlotTimestamp
	return uint64(slotAge) < in.Config.MaxCheckpointAge
}

func isFinalityProofValid(attestedHeader *consensus_core.Header, finalizedHeader *consensus_core.Header, finalityBranch []consensus_core.Bytes32) bool {
	return isProofValid(attestedHeader, finalizedHeader, finalityBranch, 6, 41)
}

func isCurrentCommitteeProofValid(attestedHeader *consensus_core.Header, currentCommittee *consensus_core.SyncComittee, currentCommitteeBranch []consensus_core.Bytes32) bool {
	return isProofValid(attestedHeader, currentCommittee, currentCommitteeBranch, 5, 22)
}

func isNextCommitteeProofValid(attestedHeader *consensus_core.Header, currentCommittee *consensus_core.SyncComittee, currentCommitteeBranch []consensus_core.Bytes32) bool {
	return isProofValid(attestedHeader, currentCommittee, currentCommitteeBranch, 5, 23)
}

func isProofValid[T TreeHashRoot](attestedHeader *consensus_core.Header, leafObject T, branch []consensus_core.Bytes32, depth, index uint64) bool {
	// Check if the branch length matches the expected depth
	if len(branch) != int(depth) {
		return false
	}

	// Get the tree hash root of the leaf object
	derivedRoot := leafObject.TreeHashRoot()
	hasher := sha256.New()

	// Iterate through the branch to derive the root
	for i, node := range branch {
		if (index/uint64(math.Pow(2, float64(i))))%2 != 0 {
			hasher.Write(node[:])        // node comes first if index is odd
			hasher.Write(derivedRoot[:]) // then the derived root
		} else {
			hasher.Write(derivedRoot[:]) // derived root comes first if index is even
			hasher.Write(node[:])        // then the node
		}

		// Reset the derived root with the updated hash
		derivedRoot = sha256.Sum256(hasher.Sum(nil))
		hasher.Reset() // Reset hasher for the next iteration
	}

	// Check if the derived root matches the state root in the attested header
	return derivedRoot == attestedHeader.State_root
}

func PayloadToBlock(value consensus_core.ExecutionPayload) (Block, error) {
	emptyNonce := "0x0000000000000000"
	emptyUncleHash := "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

	var txs []*types.Transaction

	for i, txBytes := range value.Transactions {
		// Decode the transaction envelope (RLP-encoded)
		txEnvelope, err := DecodeTxEnvelope(txBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode transaction: %v", err)
		}

		tx := Transaction{
			Hash:             txEnvelope.Hash(),
			Nonce:            txEnvelope.Nonce(),
			BlockHash:        &value.Block_hash,
			BlockNumber:      &value.Block_number,
			TransactionIndex: i,
			To:               txEnvelope.To(),
			Value:            txEnvelope.Value(),
			GasPrice:         txEnvelope.GasPrice(),
			Gas:              txEnvelope.Gas(),
			Input:            txEnvelope.Data(),
			ChainID:          txEnvelope.ChainId(),
			TransactionType:  txEnvelope.Type(),
		}

		// Handle transaction types and signatures properly based on Go-Ethereum types
		switch txEnvelope.Type() {
		case types.LegacyTxType:
			signer := types.LatestSignerForChainID(txEnvelope.ChainId())
			from, err := types.Sender(signer, txEnvelope)
			if err != nil {
				return Block{}, fmt.Errorf("failed to recover sender: %v", err)
			}
			tx.From = from.Hex()

			// Extract signature components using RawSignatureValues
			r, s, v := txEnvelope.RawSignatureValues()

			// Assign signature
			tx.Signature = &Signature{
				R: r.String(),
				S: s.String(),
				V: v.Uint64(),
			}

		case types.AccessListTxType:
			signer := types.LatestSignerForChainID(txEnvelope.ChainId())
			from, err := types.Sender(signer, txEnvelope)
			if err != nil {
				return Block{}, fmt.Errorf("failed to recover sender: %v", err)
			}
			tx.From = from.Hex()

			// Extract signature components using RawSignatureValues
			r, s, v := txEnvelope.RawSignatureValues()

			tx.Signature = &Signature{
				R:       r.String(),
				S:       s.String(),
				V:       v.Uint64(),
				YParity: &Parity{Value: v.Uint64() == 1},
			}
			tx.AccessList = txEnvelope.AccessList()

		case types.DynamicFeeTxType:
			signer := types.LatestSignerForChainID(txEnvelope.ChainId())
			from, err := types.Sender(signer, txEnvelope)
			if err != nil {
				return Block{}, fmt.Errorf("failed to recover sender: %v", err)
			}
			tx.From = from.Hex()

			// Extract signature components using RawSignatureValues
			r, s, v := txEnvelope.RawSignatureValues()

			tx.Signature = &Signature{
				R:       r.String(),
				S:       s.String(),
				V:       v.Uint64(),
				YParity: &Parity{Value: v.Uint64() == 1},
			}
			tx.AccessList = txEnvelope.AccessList()
			tx.MaxFeePerGas = &txEnvelope.MaxFeePerGas()
			tx.MaxPriorityFeePerGas = &txEnvelope.MaxPriorityFeePerGas()
			tx.GasPrice = SomeGasPrice(txEnvelope.MaxFeePerGas(), txEnvelope.MaxPriorityFeePerGas(), value.BaseFeePerGas)

		case types.BlobTxType:
			signer := types.LatestSignerForChainID(txEnvelope.ChainId())
			from, err := types.Sender(signer, txEnvelope)
			if err != nil {
				return Block{}, fmt.Errorf("failed to recover sender: %v", err)
			}
			tx.From = from.Hex()

			// Extract signature components using RawSignatureValues
			r, s, v := txEnvelope.RawSignatureValues()

			tx.Signature = &Signature{
				R:       r.String(),
				S:       s.String(),
				V:       v.Uint64(),
				YParity: &Parity{Value: v.Uint64() == 1},
			}
			tx.AccessList = txEnvelope.AccessList()
			tx.MaxFeePerGas = &txEnvelope.MaxFeePerGas()
			tx.MaxPriorityFeePerGas = &txEnvelope.MaxPriorityFeePerGas()
			tx.MaxFeePerBlobGas = &txEnvelope.MaxFeePerBlobGas()
			tx.BlobVersionedHashes = txEnvelope.BlobVersionedHashes()
			tx.GasPrice = SomeGasPrice(txEnvelope.MaxFeePerGas(), txEnvelope.MaxPriorityFeePerGas(), value.BaseFeePerGas)
		}
		// Construct and return the block
		return Block{
			Number:           value.BlockNumber(),
			BaseFeePerGas:    value.BaseFeePerGas(),
			Difficulty:       U256Zero(),
			ExtraData:        value.ExtraData(),
			GasLimit:         value.GasLimit(),
			GasUsed:          value.GasUsed(),
			Hash:             value.BlockHash(),
			LogsBloom:        value.LogsBloom(),
			Miner:            value.FeeRecipient(),
			ParentHash:       value.ParentHash(),
			ReceiptsRoot:     value.ReceiptsRoot(),
			StateRoot:        value.StateRoot(),
			Timestamp:        value.Timestamp(),
			TotalDifficulty:  U256Zero(),
			Transactions:     txs,
			MixHash:          value.PrevRandao(),
			Nonce:            emptyNonce,
			Sha3Uncles:       emptyUncleHash,
			Size:             0,
			TransactionsRoot: B256Default(),
			Uncles:           []string{},
			BlobGasUsed:      value.BlobGasUsed(),
			ExcessBlobGas:    value.ExcessBlobGas(),
		}, nil
	}
}

// getBits counts the number of bits set to 1 in a [64]byte array
func getBits(bitfield [64]byte) uint64 {
	var count uint64
	for _, b := range bitfield {
		count += uint64(popCount(b))
	}
	return count
}

// popCount counts the number of bits set to 1 in a byte
func popCount(b byte) int {
	count := 0
	for b != 0 {
		count += int(b & 1)
		b >>= 1
	}
	return count
}

// DecodeTxEnvelope takes the transaction bytes and decodes them into a transaction envelope (Ethereum transaction)
func DecodeTxEnvelope(txBytes []byte) (*types.Transaction, error) {
	// Create an empty transaction object
	var tx types.Transaction

	// Unmarshal the RLP-encoded transaction bytes into the transaction object
	err := tx.UnmarshalBinary(txBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %v", err)
	}

	return &tx, nil
}
