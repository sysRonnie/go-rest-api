package product

import (
	"go-rest-api/service/auth"
	"go-rest-api/types"
	"go-rest-api/utils"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type Handler struct {
	store     types.ProductStore
	userStore types.UserStore
}

func NewHandler(store types.ProductStore, userStore types.UserStore) *Handler {
	return &Handler{store: store, userStore: userStore}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	if h.userStore == nil {
		log.Fatal("userStore is not initialized")
	}
	router.HandleFunc("/products", auth.WithJWTAuth(h.handleCreateProduct, h.userStore)).Methods(http.MethodGet)
}

func (h *Handler) handleCreateProduct(w http.ResponseWriter, r *http.Request) {
	ps, err := h.store.GetProducts()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, ps)
}
