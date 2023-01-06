// Package libdns_ispconfig implements a DNS record management client compatible
// with the libdns interfaces for ISPConfig. TODO: Implement other entry types.
// This package only implements the management of TXT entries for ACME DNS challenges.
package libdns_ispconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with ISPConfig.
type Provider struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
	Password string `json:"password"`

	sessionId string
	authMutex sync.Mutex
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type zoneIdRequest struct {
	SessionId string `json:"session_id"`
	Origin    string `json:"origin"`
}

type zoneRequest struct {
	SessionId string `json:"session_id"`
	PrimaryId int    `json:"primary_id"`
}

type entriesRequest struct {
	SessionId string `json:"session_id"`
	ZoneId    int    `json:"zone_id"`
}

type response struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Response any    `json:"response"`
}

type changeParams struct {
	ServerId     int    `json:"server_id"`
	Name         string `json:"name"`
	Active       string `json:"active"`
	Type         string `json:"type"`
	Data         string `json:"data"`
	ZoneId       int    `json:"zone"`
	TTL          int    `json:"ttl"`
	UpdateSerial bool   `json:"update_serial"`
	Stamp        string `json:"stamp"`
}

type changeRequest struct {
	SessionId string       `json:"session_id"`
	PrimaryId string       `json:"primary_id,omitempty"`
	ClientId  any          `json:"client_id"`
	RRType    string       `json:"rr_type"`
	Params    changeParams `json:"params"`
}

type deleteRequest struct {
	SessionId string `json:"session_id"`
	PrimaryId string `json:"primary_id"`
}

func (p *Provider) apiRequest(ctx context.Context, method string, data any) response {
	endpoint := fmt.Sprintf("%s?%s", p.Endpoint, method)
	reqBody, _ := json.Marshal(data)

	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))

	if err != nil {
		panic(err)
	}

	request.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(request)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	var r response
	err = json.Unmarshal(body, &r)

	if err != nil {
		panic(err)
	}

	if r.Response == false {
		panic(string(body))
	}

	return r
}

func (p *Provider) authenticate(ctx context.Context) {

	if p.sessionId != "" {
		return
	}

	p.authMutex.Lock()

	if p.sessionId != "" {
		return
	}

	data := p.apiRequest(ctx, "login", authRequest{Username: p.Username, Password: p.Password})
	sessionId, ok := data.Response.(string)

	if !ok {
		panic("Session id corrupted")
	}
	p.sessionId = sessionId

	p.authMutex.Unlock()
}

func (p *Provider) getZoneId(ctx context.Context, origin string) int {
	if p.sessionId == "" {
		panic("Not logged in.")
	}

	if origin[len(origin)-1:] == "." {
		origin = origin[:len(origin)-1]
	}

	data := p.apiRequest(ctx, "dns_zone_get_id", zoneIdRequest{SessionId: p.sessionId, Origin: origin})

	return int(data.Response.(float64))
}

func (p *Provider) getServerId(ctx context.Context, zoneId int) int {
	if p.sessionId == "" {
		panic("Not logged in.")
	}

	data := p.apiRequest(ctx, "dns_zone_get", zoneRequest{SessionId: p.sessionId, PrimaryId: zoneId})
	entry := data.Response.(map[string]interface{})
	serverId, _ := strconv.ParseInt(entry["server_id"].(string), 10, 64)

	return int(serverId)
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.authenticate(ctx)
	zoneId := p.getZoneId(ctx, zone)
	data := p.apiRequest(ctx, "dns_rr_get_all_by_zone", entriesRequest{SessionId: p.sessionId, ZoneId: zoneId})

	var records []libdns.Record

	for _, value := range data.Response.([]interface{}) {
		entry := value.(map[string]interface{})

		ttl, _ := strconv.ParseInt(entry["ttl"].(string), 10, 64)
		priority, _ := strconv.ParseInt(entry["aux"].(string), 10, 64)

		record := libdns.Record{
			ID:       entry["id"].(string),
			Type:     entry["type"].(string),
			Name:     entry["name"].(string),
			Value:    entry["data"].(string),
			TTL:      time.Duration(ttl),
			Priority: int(priority),
		}

		records = append(records, record)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.authenticate(ctx)
	zoneId := p.getZoneId(ctx, zone)
	serverId := p.getServerId(ctx, zoneId)

	var addedRecords []libdns.Record
	for _, record := range records {
		if strings.ToLower(record.Type) == "txt" {

			ttl := int(record.TTL)

			if ttl == 0 {
				ttl = 60
			}

			change := changeRequest{
				SessionId: p.sessionId,
				ClientId:  nil,
				RRType:    "TXT",
				Params: changeParams{
					ServerId:     serverId,
					Name:         record.Name,
					Active:       "Y",
					Type:         "TXT",
					Data:         record.Value,
					ZoneId:       zoneId,
					TTL:          ttl,
					UpdateSerial: true,
					Stamp:        time.Now().Format("2006-01-02 15:04:05"),
				},
			}

			data := p.apiRequest(ctx, "dns_txt_add", change)

			record.ID = data.Response.(string)
			addedRecords = append(addedRecords, record)
		}
	}

	return addedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.authenticate(ctx)
	zoneId := p.getZoneId(ctx, zone)
	serverId := p.getServerId(ctx, zoneId)

	var addedRecords []libdns.Record
	for _, record := range records {
		if strings.ToLower(record.Type) == "txt" {
			ttl := int(record.TTL)

			if ttl == 0 {
				ttl = 60
			}

			change := changeRequest{
				SessionId: p.sessionId,
				ClientId:  nil,
				RRType:    "TXT",
				Params: changeParams{
					ServerId:     serverId,
					Name:         record.Name,
					Active:       "Y",
					Type:         "TXT",
					Data:         record.Value,
					ZoneId:       zoneId,
					TTL:          ttl,
					UpdateSerial: true,
					Stamp:        time.Now().Format("2006-01-02 15:04:05"),
				},
			}

			if record.ID != "" {
				change.PrimaryId = record.ID
			}

			p.apiRequest(ctx, "dns_txt_update", change)
			addedRecords = append(addedRecords, record)
		}
	}

	return addedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.authenticate(ctx)

	var removedRecords []libdns.Record
	for _, record := range records {
		if strings.ToLower(record.Type) == "txt" && record.ID != "" {
			p.apiRequest(ctx, "dns_txt_delete", deleteRequest{
				SessionId: p.sessionId,
				PrimaryId: record.ID,
			})
			removedRecords = append(removedRecords, record)
		}
	}

	return removedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
