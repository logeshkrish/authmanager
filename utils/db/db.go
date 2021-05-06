package db

import (
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/bluemeric/authmanager/utils/log"

	context "github.com/bluemeric/authmanager/utils/context"

	mgo "gopkg.in/mgo.v2"
)

type handle struct {
	O        interface{}
	dbName   string
	sessions []*mgo.Session
	total    int
	use      int
	count    int
}

var instantiated *handle = nil

// Instance -
func Instance() *handle {
	if instantiated == nil {
		instantiated = new(handle)
		//TODO introduce username and password
		instantiated.count = 1
		if strCount := context.Instance().Get("db-count"); strCount != "" {
			i, err := strconv.Atoi(strCount)
			if err == nil {
				instantiated.count = i
			}
		}
		log.Println("Connecting to DB:: ", context.Instance().Get("db-name"))
		instantiated.Connect(context.Instance().GetObject("db-endpoint").([]string), context.Instance().Get("db-name"))
	}
	return instantiated
}

func (h *handle) Connect(endpoint []string, dbName string) {
	log.Printf("Creating Conneciton Pool of mgo://%s/%s(%d) ", endpoint, dbName, h.count)
	for i := 0; i < h.count; i++ {
		info := &mgo.DialInfo{
			Addrs:    endpoint,
			Database: context.Instance().Get("user-db"),
			Username: context.Instance().Get("db-user"),
			Password: context.Instance().Get("db-password"),
		}

		session, err := mgo.DialWithInfo(info)
		if err != nil {
			log.Printf("Can't connect to mongo, go error %v\n", err)
			os.Exit(1)
		}

		session.SetSafe(&mgo.Safe{})
		h.addSession(session)
	}
	h.total = len(h.sessions)
	h.dbName = dbName

}

func (h *handle) Info() {
	if info, err := h.db().Session.BuildInfo(); err == nil {
		log.Printf("Created mgo://%s (%s), %d Connections", h.dbName, info.Version, h.total)
	} else {
		log.Printf("Error Connecting Database")
		os.Exit(1)
	}
}

func (h *handle) db() *mgo.Database {
	h.use = (h.use + 1) % h.total
	return h.sessions[h.use].DB(h.dbName)
}

func (h *handle) addSession(session *mgo.Session) {
	h.sessions = append(h.sessions, session)
}

func (h *handle) refresh() {
	for _, session := range h.sessions {
		session.Refresh()
	}

	log.Println("Database connection refreshed successfully!")
}

// EnsureConnection -
func EnsureConnection() {
	for {
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("Database connection is shutdown")
				Instance().refresh()
			}
		}()

		for _, session := range Instance().sessions {
			if errs := session.Ping(); errs != nil {
				log.Errorln("Database connection is shutdown:", errs)
				Instance().refresh()
				break
			}
		}

		time.Sleep(time.Duration(30) * time.Second)
	}
}

// Retry -
func Retry(Interval, TimeOut int, fn func() error) error {
	timeout := time.After(time.Duration(TimeOut) * time.Second)
	var err error
	for {
		select {
		case <-timeout:
			return err
		default:
			if err = fn(); err == nil {
				return nil
			}

			// DB connection issue
			if !strings.Contains(err.Error(), "Closed explicitly") &&
				!strings.Contains(err.Error(), "EOF") &&
				!strings.Contains(err.Error(), "interrupted at shutdown") {
				return err
			}

			log.Println("DataBase Connection Closed Explicitly, Waiting to fix", err)
			time.Sleep(time.Duration(Interval) * time.Second)
		}
	}
}

func (h *handle) Create(collection string, row interface{}) error {
	err := Retry(30, 180, func() error {
		e := h.db().C(collection).Insert(row)
		return e
	})

	return err
}

func (h *handle) ReadOne(collection string, condition interface{}) (interface{}, error) {
	var data interface{}

	err := Retry(30, 180, func() error {
		e := h.db().C(collection).Find(condition).One(&data)
		return e
	})

	return data, err
}

func (h *handle) ReadAll(collection string, query interface{}) (result []interface{}) {
	err := Retry(30, 180, func() error {
		e := h.db().C(collection).Find(query).All(&result)
		return e
	})

	if err != nil {
		log.Println("err: ", err)
	}
	return result
}

func (h *handle) Update(collection string, condition interface{}, data interface{}) error {
	err := Retry(30, 180, func() error {
		e := h.db().C(collection).Update(condition, data)
		return e
	})

	return err
}

func (h *handle) ReadPageBySort(collection string, query interface{}, field string, page int, size int) (result []interface{}, e error) {
	//bson.M{}
	//log.Printf("Page:%d, Size:%d/n", page, size)
	skip := size * (page - 1)
	//log.Println("Skip_size:", skip)

	err := Retry(30, 180, func() error {
		e := h.db().C(collection).Find(query).Limit(size).Skip(skip).Sort(field).All(&result)
		return e
	})

	return result, err
}

func (h *handle) FindAndApply(collection string, query interface{}, update interface{}) (*mgo.ChangeInfo, interface{}, error) {
	var (
		e      error
		result interface{}
		info   *mgo.ChangeInfo
	)

	change := mgo.Change{Update: update, ReturnNew: true}
	err := Retry(30, 180, func() error {
		info, e = h.db().C(collection).Find(query).Apply(change, &result)
		return e
	})

	return info, result, err
}

func (h *handle) RemoveOne(collection string, condition interface{}) error {
	//"Id"<= bson.NewObjectId()
	err := Retry(30, 180, func() error {
		e := h.db().C(collection).Remove(condition)
		return e
	})

	return err
}

func (h *handle) Count(collection string, condition interface{}) (int, error) {
	var (
		count int
		e     error
	)
	err := Retry(30, 180, func() error {
		count, e = h.db().C(collection).Find(condition).Count()
		return e
	})

	return count, err
}

func (h *handle) RemoveAll(collection string, condition interface{}) error {
	err := Retry(30, 180, func() error {
		_, e := h.db().C(collection).RemoveAll(condition)
		return e
	})

	return err
}

func (h *handle) UpdateAll(collection string, condition interface{}, data interface{}) {
	var set = make(map[string]interface{})
	set["$set"] = data
	info, err := h.db().C(collection).UpdateAll(condition, set)
	if err != nil {
		if strings.Contains(err.Error(), "Closed explicitly") {
			log.Println("DataBase Connection Closed Explicitly")
		}
	}
	log.Println("UpdateAll.Info:", info)
}

func (h *handle) ReadPage(collection string, query interface{}, page int, size int) (result []interface{}) {
	//bson.M{}
	log.Printf("Page:%d, Size:%d/n", page, size)
	skip := size * (page - 1)
	//log.Println("Skip_size:", skip)
	h.db().C(collection).Find(query).Limit(size).Skip(skip).All(&result)
	return result
}

func (h *handle) Upsert(collection string, condition interface{}, data interface{}) error {
	_, err := h.db().C(collection).Upsert(condition, data)
	if err != nil {
		if strings.Contains(err.Error(), "Closed explicitly") {
			log.Println("DataBase Connection Closed Explicitly")
		}
	}
	return err
}

func (h *handle) Distinct(collection string, condition interface{}, field string) []interface{} {
	var result []interface{}
	//"Id"<= bson.NewObjectId()
	err := h.db().C(collection).Find(condition).Distinct(field, &result)
	if err != nil {
		if strings.Contains(err.Error(), "Closed explicitly") {
			log.Println("DataBase Connection Closed Explicitly")
		}
	}
	return result
}

func (h *handle) Sort(collection string, condition interface{}, field string) []interface{} {
	var result []interface{}
	var err error
	if err = h.db().C(collection).Find(condition).Sort(field).All(&result); err != nil {
		if strings.Contains(err.Error(), "Closed explicitly") {
			log.Println("DataBase Connection Closed Explicitly")
		}
	}
	return result
}
