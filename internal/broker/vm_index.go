package broker

import (
	"errors"
	"strings"

	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/warm"
)

type imageCPUKey struct {
	Image string
	CPU   int
}

type vmMeta struct {
	WorkerID       string
	LocalVMID      string
	Virtualization string
	Image          string
	CPU            int
}

var errInvalidVMEvent = errors.New("invalid vm event")

func vmHash(workerID, localVMID string) string {
	return workerID + "|" + localVMID
}

func normalizeTuple(tuple warm.Tuple) warm.Tuple {
	tuple.Virtualization = strings.TrimSpace(tuple.Virtualization)
	tuple.Image = strings.TrimSpace(tuple.Image)
	if tuple.Virtualization == "" {
		tuple.Virtualization = "vetu"
	}
	if tuple.CPU <= 0 {
		tuple.CPU = 1
	}
	return tuple
}

func (s *Service) tupleReadySetLocked(tuple warm.Tuple) map[string]struct{} {
	tuple = normalizeTuple(tuple)
	perVirt, ok := s.readyByVirt[tuple.Virtualization]
	if !ok {
		return nil
	}
	return perVirt[imageCPUKey{Image: tuple.Image, CPU: tuple.CPU}]
}

func (s *Service) applyVMEventLocked(workerID string, event model.WorkerVMEvent) error {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return errInvalidVMEvent
	}
	if err := sandboxid.ValidateLocalVMID(event.LocalVMID); err != nil {
		return errInvalidVMEvent
	}
	tuple := normalizeTuple(warm.Tuple{
		Virtualization: event.Virtualization,
		Image:          event.Image,
		CPU:            event.CPU,
	})
	if tuple.Image == "" {
		return errInvalidVMEvent
	}

	hash := vmHash(workerID, event.LocalVMID)
	switch event.Event {
	case model.WorkerVMEventReady:
		meta := vmMeta{
			WorkerID:       workerID,
			LocalVMID:      event.LocalVMID,
			Virtualization: tuple.Virtualization,
			Image:          tuple.Image,
			CPU:            tuple.CPU,
		}
		s.upsertReadyVMLocked(hash, meta)
		return nil
	case model.WorkerVMEventClaimed, model.WorkerVMEventRetired:
		s.removeVMLocked(hash)
		return nil
	default:
		return errInvalidVMEvent
	}
}

func (s *Service) upsertReadyVMLocked(hash string, meta vmMeta) {
	if existing, ok := s.vmByHash[hash]; ok {
		s.removeReadyHashLocked(hash, existing)
	}

	perVirt, ok := s.readyByVirt[meta.Virtualization]
	if !ok {
		perVirt = make(map[imageCPUKey]map[string]struct{})
		s.readyByVirt[meta.Virtualization] = perVirt
	}
	key := imageCPUKey{Image: meta.Image, CPU: meta.CPU}
	readySet, ok := perVirt[key]
	if !ok {
		readySet = make(map[string]struct{})
		perVirt[key] = readySet
	}
	readySet[hash] = struct{}{}
	s.vmByHash[hash] = meta
}

func (s *Service) removeVMLocked(hash string) {
	meta, ok := s.vmByHash[hash]
	if !ok {
		return
	}
	s.removeReadyHashLocked(hash, meta)
}

func (s *Service) removeReadyHashLocked(hash string, meta vmMeta) {
	delete(s.vmByHash, hash)
	perVirt, ok := s.readyByVirt[meta.Virtualization]
	if !ok {
		return
	}
	key := imageCPUKey{Image: meta.Image, CPU: meta.CPU}
	readySet, ok := perVirt[key]
	if !ok {
		return
	}
	delete(readySet, hash)
	if len(readySet) == 0 {
		delete(perVirt, key)
	}
	if len(perVirt) == 0 {
		delete(s.readyByVirt, meta.Virtualization)
	}
}

func (s *Service) popReadyVMLocked(tuple warm.Tuple, hardwareSKU string) (Worker, vmMeta, bool) {
	tuple = normalizeTuple(tuple)
	readySet := s.tupleReadySetLocked(tuple)
	if len(readySet) == 0 {
		return Worker{}, vmMeta{}, false
	}
	hardwareSKU = strings.TrimSpace(hardwareSKU)

	for hash := range readySet {
		meta, ok := s.vmByHash[hash]
		if !ok {
			delete(readySet, hash)
			if len(readySet) == 0 {
				perVirt := s.readyByVirt[tuple.Virtualization]
				delete(perVirt, imageCPUKey{Image: tuple.Image, CPU: tuple.CPU})
				if len(perVirt) == 0 {
					delete(s.readyByVirt, tuple.Virtualization)
				}
			}
			continue
		}
		worker, ok := s.workersByID[meta.WorkerID]
		if !ok {
			s.removeReadyHashLocked(hash, meta)
			continue
		}
		if !worker.Available {
			continue
		}
		if hardwareSKU != "" && worker.HardwareSKU != hardwareSKU {
			continue
		}

		s.removeReadyHashLocked(hash, meta)
		return worker, meta, true
	}
	return Worker{}, vmMeta{}, false
}
