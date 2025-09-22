package models

// ImageInfo contains information about an image affected by a CVE.
type ImageInfo struct {
	ID              string    `json:"id"`
	Name            ImageName `json:"name"`
	OperatingSystem string    `json:"operatingSystem"`
	ScanTime        *time.Time `json:"scanTime"` // Using a pointer to accept 'null' values
	Priority        int64     `json:"priority"`
}

// ImageName is a sub-struct for the full image name.
type ImageName struct {
	FullName string `json:"fullName"`
}