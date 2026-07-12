package banpool

import (
	"context"
	"errors"
	"fmt"
	"log"
	"open-defender/pkg/config"
	"sync"
	"time"
)

type BanPool interface {
	BanIP(ctx context.Context, ip string, banSeconds uint64) error
	UnbanIP(ip string) error
	RestoreBans(ctx context.Context) error
}

type banPool struct {
	repository Repository
	firewall   Firewall
	mutex      sync.Mutex
}

func New(cfg *config.Config) (BanPool, error) {
	repository, err := NewRepository(cfg.BlockedIPsDatabase)
	if err != nil {
		return nil, fmt.Errorf("banpool.New() -> %w", err)
	}

	return &banPool{
		repository: repository,
		firewall:   NewFirewall(),
	}, nil
}

func (bp *banPool) RestoreBans(ctx context.Context) error {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()

	expired, err := bp.repository.GetExpired()
	if err != nil {
		return fmt.Errorf("banpool.RestoreBans() -> %w", err)
	}

	for _, ban := range expired {
		if err := bp.unban(ban.IP); err != nil {
			log.Println(err.Error())
		}
	}

	bans, err := bp.repository.GetBanned()
	if err != nil {
		return fmt.Errorf("banpool.RestoreBans() -> %w", err)
	}

	for _, ban := range bans {
		if err := bp.firewall.Ban(ban.IP); err != nil {
			log.Println(err.Error())

			if deleteErr := bp.repository.Delete(ban.ID); deleteErr != nil {
				log.Println(deleteErr.Error())
			}

			continue
		}

		go bp.waitUnban(ctx, ban)
	}

	return nil
}

func (bp *banPool) BanIP(ctx context.Context, ip string, banSeconds uint64) error {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()

	now := time.Now()

	ban := &Ban{
		IP:          ip,
		BannedAt:    now,
		BannedUntil: now.Add(time.Duration(banSeconds) * time.Second),
	}

	current, err := bp.repository.Get(ip)
	if err != nil && !errors.Is(err, ErrBanNotFound) {
		return fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
	}

	if current != nil {
		if err := bp.firewall.Ban(ip); err != nil {
			return fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
		}

		return bp.extendBan(current, ban.BannedUntil)
	}

	id, err := bp.repository.Add(ban)
	if err != nil {
		return fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
	}

	ban.ID = id

	if err := bp.firewall.Ban(ip); err != nil {
		if deleteErr := bp.repository.Delete(ban.ID); deleteErr != nil {
			log.Println(deleteErr)
		}

		return fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
	}

	go bp.waitUnban(ctx, ban)

	return nil
}

func (bp *banPool) UnbanIP(ip string) error {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()

	return bp.unban(ip)
}

func (bp *banPool) extendBan(ban *Ban, bannedUntil time.Time) error {
	if !bannedUntil.After(ban.BannedUntil) {
		return nil
	}

	ban.BannedUntil = bannedUntil

	if err := bp.repository.Update(ban); err != nil {
		return fmt.Errorf("banpool.extendBan(ip: %s) -> %w", ban.IP, err)
	}

	return nil
}

func (bp *banPool) waitUnban(ctx context.Context, ban *Ban) {
	for {
		time.Sleep(time.Until(ban.BannedUntil))
		select {
		case <-ctx.Done():
			return
		default:
		}
		bp.mutex.Lock()

		current, err := bp.repository.Get(ban.IP)
		if err != nil {
			if !errors.Is(err, ErrBanNotFound) {
				log.Println(err)
			}
			bp.mutex.Unlock()
			return
		}

		if current.ID != ban.ID {
			bp.mutex.Unlock()
			return
		}

		if current.BannedUntil.After(time.Now()) {
			ban = current
			bp.mutex.Unlock()
			continue
		}

		if err := bp.unban(ban.IP); err != nil {
			log.Println(err)
		}

		bp.mutex.Unlock()
		return
	}
}

func (bp *banPool) unban(ip string) error {
	ban, err := bp.repository.Get(ip)
	if err != nil {
		if errors.Is(err, ErrBanNotFound) {
			return nil
		}

		return fmt.Errorf("banpool.unban(ip: %s) -> %w", ip, err)
	}

	if err := bp.firewall.Unban(ip); err != nil {
		return fmt.Errorf("banpool.unban(ip: %s) -> %w", ip, err)
	}

	if err := bp.repository.Delete(ban.ID); err != nil {
		return fmt.Errorf("banpool.unban(ip: %s) -> %w", ip, err)
	}

	return nil
}
