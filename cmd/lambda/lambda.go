package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/pkg/errors"
	"github.com/r-erema/paranoid/internal/config"
	"github.com/r-erema/paranoid/internal/hasher"
)

const html = "<!DOCTYPE html><html lang=\"en\"><head> <title>Paranoid</title> <meta charset=\"utf-8\"> " +
	"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <link rel=\"stylesheet\" " +
	"href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css\" " +
	"integrity=\"sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6\" " +
	"crossorigin=\"anonymous\"/> <script src=\"https://code.jquery.com/jquery-3.6.0.min.js\" " +
	"integrity=\"sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=\" crossorigin=\"anonymous\"></script> " +
	"<script src=\"https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.1.0/jsencrypt.min.js\" " +
	"integrity=\"sha512-Tl9i44ZZYtGq56twOViooxyXCSNNkEkRmDMnPAmgU+m8B8A8LXJemzkH/sZ7y4BWi5kVVfkr75v+CQDU6Ug+yw==\" " +
	"crossorigin=\"anonymous\"></script> " +
	"<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js\" " +
	"integrity=\"sha384-JEW9xMcG8R+pH31jmWH6WWP0WintQrMb4s7ZOdauHnUtxwoG2vI5DkLtS3qm9Ekf\" " +
	"crossorigin=\"anonymous\"></script> " +
	"<script src=\"https://cdnjs.cloudflare.com/ajax/libs/clipboard.js/2.0.0/clipboard.min.js\"></script> " +
	"<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml," +
	"<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22256%22 height=%22256%22 viewBox=%220 0 100 100%22>" +
	"<rect width=%22100%22 height=%22100%22 rx=%2250%22 fill=%22%23d0021b%22></rect><path fill=%22%23fff%22 " +
	"d=%22M70.47 50.00L70.47 50.00Q70.47 55.04 69.03 59.09Q67.59 63.14 64.94 66.02Q62.28 68.90 58.50 70.43Q54.72 " +
	"71.96 50.05 71.96L50.05 71.96Q45.36 71.96 41.58 70.43Q37.80 68.90 35.10 66.02Q32.41 63.14 30.96 59.09Q29.52 " +
	"55.04 29.52 50.00L29.52 50.00Q29.52 44.96 31.01 40.91Q32.49 36.86 35.20 33.98Q37.89 31.10 41.67 29.57Q45.45 " +
	"28.04 50.05 28.04L50.05 28.04Q54.63 28.04 58.41 29.57Q62.19 31.10 64.85 33.98Q67.50 36.86 68.99 40.91Q70.47 " +
	"44.96 70.47 50.00ZM50.05 33.98L50.05 33.98Q43.92 33.98 40.41 38.21Q36.91 42.44 36.91 50.00L36.91 50.00Q36.91 " +
	"57.65 40.37 61.84Q43.83 66.02 50.05 66.02L50.05 66.02Q56.25 66.02 59.67 61.79Q63.09 57.56 63.09 50.00L63.09 " +
	"50.00Q63.09 42.44 59.63 38.21Q56.16 33.98 50.05 33.98Z%22></path></svg>\"/> <style>body,html{height:100%}" +
	"body{display:flex;align-items:center;padding-top:40px;padding-bottom:40px;background-color:#f5f5f5}" +
	".form-signin{width:100%;max-width:330px;padding:15px;margin:auto}.form-signin .checkbox{font-weight:400}" +
	".form-signin .form-floating:focus-within{z-index:2}.form-signin input[type=email]{margin-bottom:-1px;" +
	"border-bottom-right-radius:0;border-bottom-left-radius:0}.form-signin input[type=password]{margin-bottom:10px;" +
	"border-top-left-radius:0;border-top-right-radius:0}</style></head><body class=\"text-center\" > " +
	"<main class=\"form-signin\"> <form id=\"form\" > <div class=\"input-group mb-3\" > <input type=\"text\" " +
	"class=\"form-control\" name=\"input\" id=\"input\" aria-label=\"Input\" aria-describedby=\"basic-addon2\"> " +
	"<div class=\"input-group-append\"> <button class=\"btn btn-primary\" type=\"button\" " +
	"onclick=\"$('#form').submit();\"> <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" " +
	"fill=\"currentColor\" class=\"bi bi-check2\" viewBox=\"0 0 16 16\"> <path d=\"M13.854 3.646a.5.5 0 0 1 0 " +
	".708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z\"/> " +
	"</svg> </button> </div></div></form> <div id=\"result\" style=\"display: none\"> <div class=\"input-group mb-3\"> " +
	"<input type=\"text\" id=\"result-output\" class=\"form-control\" aria-label=\"Input\" " +
	"aria-describedby=\"basic-addon2\"> <div class=\"input-group-append\"> <button class=\"btn btn-success\" " +
	"id=\"copy-button\" type=\"button\" data-clipboard-action=\"copy\" data-clipboard-target=\"#result-output\" > " +
	"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" fill=\"currentColor\" " +
	"class=\"bi bi-clipboard\" viewBox=\"0 0 16 16\"> <path d=\"M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 " +
	"2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z\"/> " +
	"<path d=\"M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 " +
	"5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z\"/> </svg> </button> </div></div>" +
	"</div><div id=\"pk-block\" style=\"display: none\" > <p> <button class=\"btn btn-primary\" type=\"button\" " +
	"data-bs-toggle=\"collapse\" data-bs-target=\"#collapseExample\" aria-expanded=\"false\" " +
	"aria-controls=\"collapseExample\"> <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" " +
	"fill=\"currentColor\" class=\"bi bi-key\" viewBox=\"0 0 16 16\"> <path d=\"M0 8a4 4 0 0 1 7.465-2H14a.5.5 0 0 " +
	"1 .354.146l1.5 1.5a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0L13 9.207l-.646.647a.5.5 0 0 1-.708 " +
	"0L11 9.207l-.646.647a.5.5 0 0 1-.708 0L9 9.207l-.646.647A.5.5 0 0 1 8 10h-.535A4 4 0 0 1 0 8zm4-3a3 3 0 1 0 " +
	"2.712 4.285A.5.5 0 0 1 7.163 9h.63l.853-.854a.5.5 0 0 1 .708 0l.646.647.646-.647a.5.5 0 0 1 .708 " +
	"0l.646.647.646-.647a.5.5 0 0 1 .708 0l.646.647.793-.793-1-1h-6.63a.5.5 0 0 1-.451-.285A3 3 0 0 0 4 5z\"/> " +
	"<path d=\"M4 8a1 1 0 1 1-2 0 1 1 0 0 1 2 0z\"/> </svg> </button> </p><div class=\"collapse\" " +
	"id=\"collapseExample\"> <div class=\"mb-3\"> <label for=\"pk-input\" style=\"display: none\"></label> " +
	"<textarea class=\"form-control\" id=\"pk-input\" rows=\"3\"></textarea> </div></div></div></main>" +
	"<script>const PK_KEY=\"pk\"; new ClipboardJS(\"#copy-button\"); " +
	"if (!localStorage.getItem(PK_KEY)){$(\"#pk-block\").show();}$(\"#pk-input\").on('blur', " +
	"function (){localStorage.setItem(PK_KEY, $(this).val()); $(\"#pk-block\").hide();}); " +
	"$(\"form\").on(\"submit\", function (e){e.preventDefault(); " +
	"$.ajax({url: \"https://kvlqs3dhg5.execute-api.eu-central-1.amazonaws.com/default/paranoid\", " +
	"type: \"POST\", contentType: \"application/json\", data: JSON.stringify({input: $(\"#input\").val()}), " +
	"error: function (xhr){var sign=new JSEncrypt(); sign.setPrivateKey(localStorage.getItem(\"pk\")); " +
	"data=sign.decrypt(xhr.responseText); $(\"#form\").hide(); $(\"#result-output\").val(data); " +
	"$(\"#result\").show();},});});</script></body></html>"

type body struct {
	Input string `json:"input"`
}

func HandleRequest(r *events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if r.HTTPMethod != http.MethodPost {
		return events.APIGatewayProxyResponse{
			Headers:           map[string]string{"Content-Type": "text/html; charset=UTF-8"},
			Body:              html,
			StatusCode:        http.StatusOK,
			IsBase64Encoded:   false,
			MultiValueHeaders: map[string][]string{},
		}, nil
	}

	var b body

	err := json.Unmarshal([]byte(r.Body), &b)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:              err.Error(),
			StatusCode:        http.StatusBadRequest,
			Headers:           map[string]string{},
			IsBase64Encoded:   false,
			MultiValueHeaders: map[string][]string{},
		}, fmt.Errorf("unmarshalling: %w", err)
	}

	if b.Input == "" {
		return events.APIGatewayProxyResponse{
			Body:              errors.New("empty input").Error(),
			StatusCode:        http.StatusBadRequest,
			Headers:           map[string]string{},
			IsBase64Encoded:   false,
			MultiValueHeaders: map[string][]string{},
		}, nil
	}

	h := hasher.Hash(b.Input, config.Salt)

	publicKey, err := bytesToPublicKey([]byte(config.PublicKeyData))
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:              errors.Wrap(err, "bytes to public key").Error(),
			StatusCode:        http.StatusInternalServerError,
			Headers:           map[string]string{},
			IsBase64Encoded:   false,
			MultiValueHeaders: map[string][]string{},
		}, nil
	}

	encryptedData, err := EncryptWithPublicKey([]byte(h), publicKey)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:              errors.Wrap(err, "encryption with public key").Error(),
			StatusCode:        http.StatusInternalServerError,
			Headers:           map[string]string{},
			IsBase64Encoded:   false,
			MultiValueHeaders: map[string][]string{},
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:              base64.StdEncoding.EncodeToString(encryptedData),
		StatusCode:        http.StatusOK,
		Headers:           map[string]string{},
		IsBase64Encoded:   false,
		MultiValueHeaders: map[string][]string{},
	}, nil
}

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return nil, fmt.Errorf("data encryption: %w", err)
	}

	return ciphertext, nil
}

func bytesToPublicKey(pub []byte) (key *rsa.PublicKey, err error) {
	block, _ := pem.Decode(pub)
	b := block.Bytes

	var ifc interface{}

	ifc, err = x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key type casting: %w", err)
	}

	return key, nil
}

func main() {
	lambda.Start(HandleRequest)
}
