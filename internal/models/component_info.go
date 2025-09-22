package models

// ComponentInfo represents an image or node component.
type ComponentInfo struct {
    Name    string `json:"name"`
    Version string `json:"version"`
    FixedIn string `json:"fixedIn"`
}