package data

import (
	"context"
	"crypto/tls"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/kerberos/internal/config"
	stls "github.com/scorpio-id/kerberos/internal/tls"

)

type Persistence struct {
	Client  *redis.Client
	Context context.Context
	cfg     config.Config
}

func NewPersistenceClient(cfg config.Config) Persistence {
	// FIXME: See if we can prevent Redis Options auto connect
	// TODO read documentation on rdb.Close() usage
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Persistence.Host + ":" + cfg.Persistence.Port,
		Username: cfg.Persistence.User,
		Password: cfg.Persistence.Password,
		DB:       cfg.Persistence.Database,
		// TODO enable TLS for redis >_>;
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})

	// Test the connection with a Ping command
	// pong, err := rdb.Ping(context.Background()).Result()
	// if err != nil {
	// 	log.Fatalf("Failed to connect to Redis: %v", err)
	// }

	// TODO remove print statement!
	// fmt.Println("Connected to Redis! Response:", pong)

	// WARNING wiping DB for testing purposes ...
	// fmt.Println("Flushing DB for testing purposes ...")
	// err := rdb.FlushAll(context.Background()).Err()
	// if err != nil {
	//     fmt.Println("Failed to flush DB!")
	// }

	return Persistence{
		Client:  rdb,
		Context: context.Background(),
		cfg:     cfg,
	}
}

func (persist *Persistence) SetPKCS12(pfx []byte) error {
	err := persist.Client.Set(persist.Context, "pfx:", string(pfx), 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (persist *Persistence) GetPKCS12() ([]byte, error) {
	result, err := persist.Client.Get(persist.Context, "pfx:").Result()
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}


func (p *Persistence) LoadWebPKCS12() ([]byte, error) {
	if !p.cfg.Persistence.Enabled {
		return stls.RetrieveTLSCertificate(p.cfg)
	}
	
	pkcs, err := p.GetPKCS12()
	// case: persistence is enabled, but PKCS12 does not exist
	if err == redis.Nil {
		pkcs, err := stls.RetrieveTLSCertificate(p.cfg)
		if err != nil {
			return nil, err
		}

		err = p.SetPKCS12(pkcs)
		if err != nil {
			return nil, err
		}
	}
	
	if err != nil {
		return nil, err
	}

	return pkcs, nil
}