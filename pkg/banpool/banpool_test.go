package banpool_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"open-defender/pkg/banpool"
	"open-defender/pkg/banpool/mocks"
	"open-defender/pkg/config"

	"go.uber.org/mock/gomock"
)

type fakeResult struct {
	lastID   int64
	affected int64
	err      error
}

func (f fakeResult) LastInsertId() (int64, error) { return f.lastID, f.err }
func (f fakeResult) RowsAffected() (int64, error) { return f.affected, f.err }

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestNewBanPool(t *testing.T) {
	cfg := config.New()
	cfg.BlockedIPsDatabase = filepath.Join(t.TempDir(), "blocked.db")

	if _, err := banpool.New(cfg); err != nil {
		t.Fatalf("New() error: %v", err)
	}
}

func TestNewBanPoolBadPath(t *testing.T) {
	cfg := config.New()
	cfg.BlockedIPsDatabase = "/proc/nonexistent/blocked.db"

	if _, err := banpool.New(cfg); err == nil {
		t.Fatal("New() error = nil, want failure")
	}
}

func TestBanIP(t *testing.T) {
	t.Run("new address", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrBanNotFound)
		repo.EXPECT().Add(gomock.Any()).Return(int64(42), nil)
		fw.EXPECT().Ban("1.2.3.4").Return(nil)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(cancelledContext(), "1.2.3.4", 0); err != nil {
			t.Fatalf("BanIP() error: %v", err)
		}
	})

	t.Run("get error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrCantGetBan)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 60); !errors.Is(err, banpool.ErrCantGetBan) {
			t.Fatalf("BanIP() error = %v, want ErrCantGetBan", err)
		}
	})

	t.Run("add error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrBanNotFound)
		repo.EXPECT().Add(gomock.Any()).Return(int64(0), banpool.ErrCantAddBan)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 60); !errors.Is(err, banpool.ErrCantAddBan) {
			t.Fatalf("BanIP() error = %v, want ErrCantAddBan", err)
		}
	})

	t.Run("firewall failure rolls back", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrBanNotFound)
		repo.EXPECT().Add(gomock.Any()).Return(int64(42), nil)
		fw.EXPECT().Ban("1.2.3.4").Return(banpool.ErrCantBanIP)
		repo.EXPECT().Delete(int64(42)).Return(banpool.ErrCantDeleteBan)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 60); !errors.Is(err, banpool.ErrCantBanIP) {
			t.Fatalf("BanIP() error = %v, want ErrCantBanIP", err)
		}
	})

	t.Run("existing extends", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		existing := &banpool.Ban{ID: 7, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)}
		repo.EXPECT().Get("1.2.3.4").Return(existing, nil)
		fw.EXPECT().Ban("1.2.3.4").Return(nil)
		repo.EXPECT().Update(gomock.Any()).Return(nil)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 600); err != nil {
			t.Fatalf("BanIP() error: %v", err)
		}
	})

	t.Run("existing update error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		existing := &banpool.Ban{ID: 7, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)}
		repo.EXPECT().Get("1.2.3.4").Return(existing, nil)
		fw.EXPECT().Ban("1.2.3.4").Return(nil)
		repo.EXPECT().Update(gomock.Any()).Return(banpool.ErrCantUpdateBan)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 600); !errors.Is(err, banpool.ErrCantUpdateBan) {
			t.Fatalf("BanIP() error = %v, want ErrCantUpdateBan", err)
		}
	})

	t.Run("existing no extend", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		existing := &banpool.Ban{ID: 7, IP: "1.2.3.4", BannedUntil: time.Now().Add(24 * time.Hour)}
		repo.EXPECT().Get("1.2.3.4").Return(existing, nil)
		fw.EXPECT().Ban("1.2.3.4").Return(nil)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 1); err != nil {
			t.Fatalf("BanIP() error: %v", err)
		}
	})

	t.Run("existing firewall error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		existing := &banpool.Ban{ID: 7, IP: "1.2.3.4", BannedUntil: time.Now().Add(time.Hour)}
		repo.EXPECT().Get("1.2.3.4").Return(existing, nil)
		fw.EXPECT().Ban("1.2.3.4").Return(banpool.ErrCantBanIP)

		if err := banpool.NewBanPoolForTest(repo, fw).BanIP(context.Background(), "1.2.3.4", 600); !errors.Is(err, banpool.ErrCantBanIP) {
			t.Fatalf("BanIP() error = %v, want ErrCantBanIP", err)
		}
	})
}

func TestUnbanIP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(&banpool.Ban{ID: 3, IP: "1.2.3.4"}, nil)
		fw.EXPECT().Unban("1.2.3.4").Return(nil)
		repo.EXPECT().Delete(int64(3)).Return(nil)

		if err := banpool.NewBanPoolForTest(repo, fw).UnbanIP("1.2.3.4"); err != nil {
			t.Fatalf("UnbanIP() error: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrBanNotFound)

		if err := banpool.NewBanPoolForTest(repo, fw).UnbanIP("1.2.3.4"); err != nil {
			t.Fatalf("UnbanIP() error = %v, want nil", err)
		}
	})

	t.Run("get error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrCantGetBan)

		if err := banpool.NewBanPoolForTest(repo, fw).UnbanIP("1.2.3.4"); !errors.Is(err, banpool.ErrCantGetBan) {
			t.Fatalf("UnbanIP() error = %v, want ErrCantGetBan", err)
		}
	})

	t.Run("firewall error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(&banpool.Ban{ID: 1, IP: "1.2.3.4"}, nil)
		fw.EXPECT().Unban("1.2.3.4").Return(banpool.ErrCantUnbanIP)

		if err := banpool.NewBanPoolForTest(repo, fw).UnbanIP("1.2.3.4"); !errors.Is(err, banpool.ErrCantUnbanIP) {
			t.Fatalf("UnbanIP() error = %v, want ErrCantUnbanIP", err)
		}
	})

	t.Run("delete error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(&banpool.Ban{ID: 1, IP: "1.2.3.4"}, nil)
		fw.EXPECT().Unban("1.2.3.4").Return(nil)
		repo.EXPECT().Delete(int64(1)).Return(banpool.ErrCantDeleteBan)

		if err := banpool.NewBanPoolForTest(repo, fw).UnbanIP("1.2.3.4"); !errors.Is(err, banpool.ErrCantDeleteBan) {
			t.Fatalf("UnbanIP() error = %v, want ErrCantDeleteBan", err)
		}
	})
}

func TestRestoreBans(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		active := &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now()}
		repo.EXPECT().GetExpired().Return(nil, nil)
		repo.EXPECT().GetBanned().Return([]*banpool.Ban{active}, nil)
		fw.EXPECT().Ban("1.2.3.4").Return(nil)

		if err := banpool.NewBanPoolForTest(repo, fw).RestoreBans(cancelledContext()); err != nil {
			t.Fatalf("RestoreBans() error: %v", err)
		}
	})

	t.Run("expired unban and ban failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		expired := &banpool.Ban{ID: 1, IP: "1.1.1.1"}
		active := &banpool.Ban{ID: 2, IP: "2.2.2.2", BannedUntil: time.Now().Add(time.Hour)}
		repo.EXPECT().GetExpired().Return([]*banpool.Ban{expired}, nil)
		repo.EXPECT().Get("1.1.1.1").Return(expired, nil)
		fw.EXPECT().Unban("1.1.1.1").Return(nil)
		repo.EXPECT().Delete(int64(1)).Return(nil)
		repo.EXPECT().GetBanned().Return([]*banpool.Ban{active}, nil)
		fw.EXPECT().Ban("2.2.2.2").Return(banpool.ErrCantBanIP)
		repo.EXPECT().Delete(int64(2)).Return(banpool.ErrCantDeleteBan)

		if err := banpool.NewBanPoolForTest(repo, fw).RestoreBans(cancelledContext()); err != nil {
			t.Fatalf("RestoreBans() error: %v", err)
		}
	})

	t.Run("expired unban error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		expired := &banpool.Ban{ID: 1, IP: "1.1.1.1"}
		repo.EXPECT().GetExpired().Return([]*banpool.Ban{expired}, nil)
		repo.EXPECT().Get("1.1.1.1").Return(nil, banpool.ErrCantGetBan)
		repo.EXPECT().GetBanned().Return(nil, nil)

		if err := banpool.NewBanPoolForTest(repo, fw).RestoreBans(context.Background()); err != nil {
			t.Fatalf("RestoreBans() error: %v", err)
		}
	})

	t.Run("get expired error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().GetExpired().Return(nil, banpool.ErrCantGetBannedIPs)

		if err := banpool.NewBanPoolForTest(repo, fw).RestoreBans(context.Background()); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
			t.Fatalf("RestoreBans() error = %v, want ErrCantGetBannedIPs", err)
		}
	})

	t.Run("get banned error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().GetExpired().Return(nil, nil)
		repo.EXPECT().GetBanned().Return(nil, banpool.ErrCantGetBannedIPs)

		if err := banpool.NewBanPoolForTest(repo, fw).RestoreBans(context.Background()); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
			t.Fatalf("RestoreBans() error = %v, want ErrCantGetBannedIPs", err)
		}
	})
}

func TestWaitUnban(t *testing.T) {
	t.Run("context cancelled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		bp := banpool.NewBanPoolForTest(repo, fw)
		banpool.WaitUnbanForTest(bp, cancelledContext(), &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)})
	})

	t.Run("ban not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrBanNotFound)
		bp := banpool.NewBanPoolForTest(repo, fw)
		banpool.WaitUnbanForTest(bp, context.Background(), &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)})
	})

	t.Run("get error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(nil, banpool.ErrCantGetBan)
		bp := banpool.NewBanPoolForTest(repo, fw)
		banpool.WaitUnbanForTest(bp, context.Background(), &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)})
	})

	t.Run("replaced ban", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)
		repo.EXPECT().Get("1.2.3.4").Return(&banpool.Ban{ID: 99, IP: "1.2.3.4"}, nil)
		bp := banpool.NewBanPoolForTest(repo, fw)
		banpool.WaitUnbanForTest(bp, context.Background(), &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)})
	})

	t.Run("still active then expires", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRepository(ctrl)
		fw := mocks.NewMockFirewall(ctrl)

		calls := 0
		repo.EXPECT().Get("1.2.3.4").DoAndReturn(func(string) (*banpool.Ban, error) {
			calls++
			if calls == 1 {
				return &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(20 * time.Millisecond)}, nil
			}
			return &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)}, nil
		}).Times(3)
		fw.EXPECT().Unban("1.2.3.4").Return(banpool.ErrCantUnbanIP)

		bp := banpool.NewBanPoolForTest(repo, fw)
		banpool.WaitUnbanForTest(bp, context.Background(), &banpool.Ban{ID: 1, IP: "1.2.3.4", BannedUntil: time.Now().Add(-time.Minute)})
	})
}

func newRow(t *testing.T, ctrl *gomock.Controller, id int64, ip string, scanErr error) *mocks.MockRow {
	row := mocks.NewMockRow(ctrl)
	row.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(dest ...any) error {
		if scanErr != nil {
			return scanErr
		}
		*dest[0].(*int64) = id
		*dest[1].(*string) = ip
		*dest[2].(*time.Time) = time.Now()
		*dest[3].(*time.Time) = time.Now()
		return nil
	})
	return row
}

func TestRepositoryAdd(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fakeResult{lastID: 99}, nil)

		id, err := banpool.NewRepositoryForTest(db).Add(&banpool.Ban{IP: "1.2.3.4"})
		if err != nil || id != 99 {
			t.Fatalf("Add() = %d, %v; want 99, nil", id, err)
		}
	})

	t.Run("exec error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("boom"))

		if _, err := banpool.NewRepositoryForTest(db).Add(&banpool.Ban{IP: "1.2.3.4"}); !errors.Is(err, banpool.ErrCantAddBan) {
			t.Fatalf("Add() error = %v, want ErrCantAddBan", err)
		}
	})

	t.Run("last insert id error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fakeResult{err: errors.New("boom")}, nil)

		if _, err := banpool.NewRepositoryForTest(db).Add(&banpool.Ban{IP: "1.2.3.4"}); !errors.Is(err, banpool.ErrCantAddBan) {
			t.Fatalf("Add() error = %v, want ErrCantAddBan", err)
		}
	})
}

func TestRepositoryGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().QueryRow(gomock.Any(), gomock.Any()).Return(newRow(t, ctrl, 5, "1.2.3.4", nil))

		ban, err := banpool.NewRepositoryForTest(db).Get("1.2.3.4")
		if err != nil || ban.ID != 5 {
			t.Fatalf("Get() = %+v, %v; want id 5", ban, err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().QueryRow(gomock.Any(), gomock.Any()).Return(newRow(t, ctrl, 0, "", sql.ErrNoRows))

		if _, err := banpool.NewRepositoryForTest(db).Get("1.2.3.4"); !errors.Is(err, banpool.ErrBanNotFound) {
			t.Fatalf("Get() error = %v, want ErrBanNotFound", err)
		}
	})

	t.Run("scan error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().QueryRow(gomock.Any(), gomock.Any()).Return(newRow(t, ctrl, 0, "", errors.New("boom")))

		if _, err := banpool.NewRepositoryForTest(db).Get("1.2.3.4"); !errors.Is(err, banpool.ErrCantGetBan) {
			t.Fatalf("Get() error = %v, want ErrCantGetBan", err)
		}
	})
}

func TestRepositoryListQueries(t *testing.T) {
	cases := []struct {
		name string
		call func(banpool.Repository) ([]*banpool.Ban, error)
	}{
		{"GetBanned", func(r banpool.Repository) ([]*banpool.Ban, error) { return r.GetBanned() }},
		{"GetExpired", func(r banpool.Repository) ([]*banpool.Ban, error) { return r.GetExpired() }},
	}

	for _, tc := range cases {
		t.Run(tc.name+" success", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			db := mocks.NewMockDB(ctrl)
			rows := mocks.NewMockRows(ctrl)
			gomock.InOrder(
				rows.EXPECT().Next().Return(true),
				rows.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
				rows.EXPECT().Next().Return(false),
			)
			rows.EXPECT().Err().Return(nil)
			rows.EXPECT().Close().Return(nil)
			db.EXPECT().Query(gomock.Any(), gomock.Any()).Return(rows, nil)

			bans, err := tc.call(banpool.NewRepositoryForTest(db))
			if err != nil || len(bans) != 1 {
				t.Fatalf("%s() = %v, %v; want one ban", tc.name, bans, err)
			}
		})

		t.Run(tc.name+" query error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			db := mocks.NewMockDB(ctrl)
			db.EXPECT().Query(gomock.Any(), gomock.Any()).Return(nil, errors.New("boom"))

			if _, err := tc.call(banpool.NewRepositoryForTest(db)); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
				t.Fatalf("%s() error = %v, want ErrCantGetBannedIPs", tc.name, err)
			}
		})

		t.Run(tc.name+" scan error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			db := mocks.NewMockDB(ctrl)
			rows := mocks.NewMockRows(ctrl)
			gomock.InOrder(
				rows.EXPECT().Next().Return(true),
				rows.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("boom")),
			)
			rows.EXPECT().Close().Return(nil)
			db.EXPECT().Query(gomock.Any(), gomock.Any()).Return(rows, nil)

			if _, err := tc.call(banpool.NewRepositoryForTest(db)); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
				t.Fatalf("%s() error = %v, want ErrCantGetBannedIPs", tc.name, err)
			}
		})

		t.Run(tc.name+" rows error", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			db := mocks.NewMockDB(ctrl)
			rows := mocks.NewMockRows(ctrl)
			rows.EXPECT().Next().Return(false)
			rows.EXPECT().Err().Return(errors.New("boom"))
			rows.EXPECT().Close().Return(nil)
			db.EXPECT().Query(gomock.Any(), gomock.Any()).Return(rows, nil)

			if _, err := tc.call(banpool.NewRepositoryForTest(db)); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
				t.Fatalf("%s() error = %v, want ErrCantGetBannedIPs", tc.name, err)
			}
		})
	}
}

func TestRepositoryUpdate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fakeResult{affected: 1}, nil)

		if err := banpool.NewRepositoryForTest(db).Update(&banpool.Ban{ID: 1, IP: "1.2.3.4"}); err != nil {
			t.Fatalf("Update() error: %v", err)
		}
	})

	t.Run("exec error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("boom"))

		if err := banpool.NewRepositoryForTest(db).Update(&banpool.Ban{ID: 1, IP: "1.2.3.4"}); !errors.Is(err, banpool.ErrCantUpdateBan) {
			t.Fatalf("Update() error = %v, want ErrCantUpdateBan", err)
		}
	})

	t.Run("rows affected error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fakeResult{err: errors.New("boom")}, nil)

		if err := banpool.NewRepositoryForTest(db).Update(&banpool.Ban{ID: 1, IP: "1.2.3.4"}); !errors.Is(err, banpool.ErrCantUpdateBan) {
			t.Fatalf("Update() error = %v, want ErrCantUpdateBan", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fakeResult{affected: 0}, nil)

		if err := banpool.NewRepositoryForTest(db).Update(&banpool.Ban{ID: 1, IP: "1.2.3.4"}); !errors.Is(err, banpool.ErrBanNotFound) {
			t.Fatalf("Update() error = %v, want ErrBanNotFound", err)
		}
	})
}

func TestRepositoryDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(fakeResult{}, nil)

		if err := banpool.NewRepositoryForTest(db).Delete(1); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}
	})

	t.Run("exec error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		db := mocks.NewMockDB(ctrl)
		db.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, errors.New("boom"))

		if err := banpool.NewRepositoryForTest(db).Delete(1); !errors.Is(err, banpool.ErrCantDeleteBan) {
			t.Fatalf("Delete() error = %v, want ErrCantDeleteBan", err)
		}
	})
}

func TestRepositoryClose(t *testing.T) {
	ctrl := gomock.NewController(t)
	db := mocks.NewMockDB(ctrl)
	db.EXPECT().Close().Return(nil)

	if err := banpool.NewRepositoryForTest(db).Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func TestRepositorySQLite(t *testing.T) {
	repo, err := banpool.NewRepository(filepath.Join(t.TempDir(), "nested", "blocked.db"))
	if err != nil {
		t.Fatalf("NewRepository() error: %v", err)
	}
	defer repo.Close()

	now := time.Now().Truncate(time.Second)
	id, err := repo.Add(&banpool.Ban{IP: "1.1.1.1", BannedAt: now, BannedUntil: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Add() error: %v", err)
	}
	if _, err := repo.Add(&banpool.Ban{IP: "2.2.2.2", BannedAt: now.Add(-2 * time.Hour), BannedUntil: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	ban, err := repo.Get("1.1.1.1")
	if err != nil || ban.ID != id {
		t.Fatalf("Get() = %+v, %v", ban, err)
	}
	if _, err := repo.Get("9.9.9.9"); !errors.Is(err, banpool.ErrBanNotFound) {
		t.Fatalf("Get(absent) error = %v, want ErrBanNotFound", err)
	}

	banned, err := repo.GetBanned()
	if err != nil || len(banned) != 1 || banned[0].IP != "1.1.1.1" {
		t.Fatalf("GetBanned() = %v, %v", banned, err)
	}
	expired, err := repo.GetExpired()
	if err != nil || len(expired) != 1 || expired[0].IP != "2.2.2.2" {
		t.Fatalf("GetExpired() = %v, %v", expired, err)
	}

	if err := repo.Update(&banpool.Ban{ID: id, IP: "1.1.1.1", BannedAt: now, BannedUntil: now.Add(3 * time.Hour)}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
	if err := repo.Update(&banpool.Ban{ID: 404, IP: "x", BannedAt: now, BannedUntil: now}); !errors.Is(err, banpool.ErrBanNotFound) {
		t.Fatalf("Update(absent) error = %v, want ErrBanNotFound", err)
	}

	if err := repo.Delete(id); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
}

func TestRepositorySQLiteClosed(t *testing.T) {
	repo, err := banpool.NewRepository(filepath.Join(t.TempDir(), "blocked.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.GetBanned(); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
		t.Errorf("GetBanned() on closed db error = %v", err)
	}
	if _, err := repo.GetExpired(); !errors.Is(err, banpool.ErrCantGetBannedIPs) {
		t.Errorf("GetExpired() on closed db error = %v", err)
	}
}
