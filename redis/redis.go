package redis

import (
	"encoding/json"
	"fmt"
	"gopaddle/domainmanager/utils/context"
	"time"

	"github.com/garyburd/redigo/redis"
)

//RedisCli is
type RedisCli struct {
	pool *redis.Pool // To Create Pool of Redis Connection
}

//Redistest is
type Redistest struct {
	Name string `json:"name,omitempty"`
	Vars string `json:"vars,omitempty"`
	Vari string `json:"vari,omitempty"`
}

var pool *RedisCli = nil

//Connect is To Establish a Connection To Redis
func Connect() *RedisCli {
	//redis.
	if pool == nil {
		return &RedisCli{
			pool: &redis.Pool{
				MaxIdle:     32,
				IdleTimeout: 240 * time.Second,
				Dial: func() (redis.Conn, error) {
					fmt.Println("****inside redis connect function****")
					fmt.Println(context.Instance().Get("redis-endpoint") + ":" + context.Instance().Get("redis-port"))
					c, err := redis.Dial("tcp", context.Instance().Get("redis-endpoint")+":"+context.Instance().Get("redis-port"))
					if err != nil {
						fmt.Println("failed to connect redis", err)
						return nil, err
						//return errors.New("failed to connect redis", err)
					}
					if _, err := c.Do("AUTH", context.Instance().Get("redis-password")); err != nil {
						fmt.Println("failed to connect redis1", err)
						c.Close()
						return nil, err
					}

					return c, err
				},
				TestOnBorrow: func(c redis.Conn, t time.Time) error {
					_, err := c.Do("PING")
					return err
				},
			},
		}

	}
	fmt.Println(" Redis Server Connection Established")
	return pool
}

//To Set The Value on Redis as Key Pair
func (redisCli *RedisCli) SetValue(key string, value string, expiration ...interface{}) error {
	_, err := redisCli.pool.Get().Do("SET", key, value)

	if err == nil && expiration != nil {
		redisCli.pool.Get().Do("EXPIRE", key, expiration[0])
	}
	return err
}

//To Set The Value on Redis as Key Pair
func (redisCli *RedisCli) SetHM(key string, value Redistest, expiration ...interface{}) error {
	jason, _ := json.Marshal(value)
	_, err := redisCli.pool.Get().Do("SET", key, jason)

	if err == nil && expiration != nil {
		redisCli.pool.Get().Do("EXPIRE", key, expiration[0])
	}
	return err
}

//To Get The Value from Redis by Using Key
func (redisCli *RedisCli) GetValue(key string) (interface{}, error) {
	return redisCli.pool.Get().Do("GET", key)
}

//To Get The Value from Redis by Using Key
func (redisCli *RedisCli) GetStruct(key string) (Redistest, error) {
	var result Redistest
	val, err := redis.String(redisCli.pool.Get().Do("GET", key))
	if err != nil {
		fmt.Println(err)
	}
	json.Unmarshal([]byte(val), &result)
	return result, err
}

//To Get The Value from Redis by Using Key
func (redisCli *RedisCli) GetStringValue(key string) (string, error) {
	return redis.String(redisCli.pool.Get().Do("GET", key))
}

//To Remove the Key Pair from Redis
func (redisCli *RedisCli) DelValue(key string) (interface{}, error) {
	return redisCli.pool.Get().Do("DEL", key)
}

//To Count The Key Size which is Store in Redis Server
func (redisCli *RedisCli) GetCount() (interface{}, error) {
	return redisCli.pool.Get().Do("DBSIZE")
}

/*
func GetLogger() {
	log = logs.GetLogger()
}
*/
