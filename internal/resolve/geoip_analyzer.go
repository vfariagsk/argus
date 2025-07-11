package resolve

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type GeoIPInfo struct {
	Country string  `json:"country"`
	City    string  `json:"city"`
	ISP     string  `json:"isp"`
	ASN     string  `json:"asn"`
	ASName  string  `json:"as_name"`
	Lat     float64 `json:"lat"`
	Long    float64 `json:"long"`
}

type GeoIPAnalyzer struct {
	client *http.Client
	config DNSConfig
}

func NewGeoIPAnalyzer(config DNSConfig) *GeoIPAnalyzer {
	return &GeoIPAnalyzer{
		client: &http.Client{
			Timeout: 2 * time.Second,
		},
		config: config,
	}
}

func (ga *GeoIPAnalyzer) Lookup(ip string) (*GeoIPInfo, error) {
	if info, err := ga.lookupGeoLite2(ip, ""); err == nil {
		return info, nil
	}

	apis := []func(string, string) (*GeoIPInfo, error){
		ga.lookupIPInfo,
		ga.lookupIPGeolocation,
	}

	for _, api := range apis {
		if info, err := api(ip, ga.config.IPGeoLocationKey); err == nil {
			return info, nil
		}
	}

	return &GeoIPInfo{}, fmt.Errorf("all GeoIP APIs failed")
}
func (ga *GeoIPAnalyzer) lookupGeoLite2(ip string, _ string) (*GeoIPInfo, error) {
	db, err := maxminddb.Open("assets/GeoLite2-City.mmdb")
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoLite2 database: %v", err)
	}
	defer db.Close()

	var record struct {
		Country struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}

	ipAddr := net.ParseIP(ip)
	if err := db.Lookup(ipAddr, &record); err != nil {
		return nil, fmt.Errorf("failed to lookup IP in GeoLite2 database: %v", err)
	}

	country := record.Country.Names["en"]
	city := record.City.Names["en"]
	lat := record.Location.Latitude
	long := record.Location.Longitude

	return &GeoIPInfo{
		Country: country,
		City:    city,
		Lat:     lat,
		Long:    long,
	}, nil
}

func (ga *GeoIPAnalyzer) lookupIPInfo(ip string, _ string) (*GeoIPInfo, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ga.config.UserAgent)

	resp, err := ga.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Country string `json:"country"`
		City    string `json:"city"`
		Org     string `json:"org"`
		ASN     string `json:"asn"`
		Loc     string `json:"loc"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	lat, long, err := parseLocation(result.Loc)
	if err != nil {
		return nil, err
	}

	return &GeoIPInfo{
		Country: result.Country,
		City:    result.City,
		ISP:     result.Org,
		ASN:     result.ASN,
		ASName:  result.Org,
		Lat:     lat,
		Long:    long,
	}, nil
}

func (ga *GeoIPAnalyzer) lookupIPGeolocation(ip string, apiKey string) (*GeoIPInfo, error) {
	url := fmt.Sprintf("https://api.ipgeolocation.io/ipgeo?apiKey=%s&ip=%s", apiKey, ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ga.config.UserAgent)

	resp, err := ga.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		CountryName string `json:"country_name"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		ASN         string `json:"asn"`
		ASName      string `json:"as"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &GeoIPInfo{
		Country: result.CountryName,
		City:    result.City,
		ISP:     result.ISP,
		ASN:     result.ASN,
		ASName:  result.ASName,
	}, nil
}

func parseLocation(loc string) (float64, float64, error) {
	parts := strings.Split(loc, ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid location format")
	}

	lat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, 0, err
	}
	long, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return 0, 0, err
	}

	return lat, long, nil
}
