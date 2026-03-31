package handler

import "net/http"

type OpenAPIHandler struct {
	filePath string
}

func NewOpenAPIHandler(filePath string) *OpenAPIHandler {
	return &OpenAPIHandler{filePath: filePath}
}

func (h *OpenAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	http.ServeFile(w, r, h.filePath)
}
