package main

type userDocument struct {
	Avatar struct {
		URI string `json:"uri"`
	} `json:"avatar"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type userData struct {
	Scopes   []string `json:"scopes"`
	UserData struct {
		ConnectionAddr string `json:"connection_addr"`
		ID             string `json:"id"`
	} `json:"user_data"`
}

type accessToken struct {
	AccessToken string `json:"access_token"`
}

type dockIoEvent struct {
	EventName string `json:"event_name"`
	EventData struct {
		ConnectionAddr string `json:"connection_addr"`
		IpfsAddr       string `json:"ipfs_addr"`
	} `json:"event_data"`
	Secret string `json:"secret"`
}

type basicUserProfileSchema struct {
	CreatedAt string `json:"$createdAt"`
	Data      struct {
		Avatar    interface{} `json:"avatar"`
		FirstName string      `json:"firstName"`
		LastName  string      `json:"lastName"`
	} `json:"$data"`
	OriginAddress    string `json:"$originAddress"`
	RecipientAddress string `json:"$recipientAddress"`
	Schema           string `json:"$schema"`
}

type emailSchema struct {
	CreatedAt string `json:"$createdAt"`
	Data      struct {
		Email string `json:"email"`
	} `json:"$data"`
	OriginAddress    string `json:"$originAddress"`
	RecipientAddress string `json:"$recipientAddress"`
	Schema           string `json:"$schema"`
}
