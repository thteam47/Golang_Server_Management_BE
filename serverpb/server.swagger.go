package serverpb

const (
	Swagger = `
	{
		"swagger": "2.0",
		"info": {
		  "title": "server.proto",
		  "version": "version not set"
		},
		"tags": [
		  {
			"name": "ServerService"
		  }
		],
		"consumes": [
		  "application/json"
		],
		"produces": [
		  "application/json"
		],
		"paths": {
		  "/addServer": {
			"post": {
			  "operationId": "ServerService_addServer",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverResponseServer"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"$ref": "#/definitions/serverServer"
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/admin": {
			"post": {
			  "operationId": "ServerService_login",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverResultLogin"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"$ref": "#/definitions/serverLoginServer"
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/changePassword/{idServer}": {
			"put": {
			  "operationId": "ServerService_changePassword",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverMessResponse"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "idServer",
				  "in": "path",
				  "required": true,
				  "type": "string"
				},
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"type": "object",
					"properties": {
					  "password": {
						"type": "string"
					  }
					}
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/changeStatus": {
			"post": {
			  "operationId": "ServerService_updateStatus",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverMessResponse"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"$ref": "#/definitions/serverChangeStatusRequest"
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/dashboard/{limitPage}/{numberPage}": {
			"get": {
			  "operationId": "ServerService_index",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverListServer"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "limitPage",
				  "in": "path",
				  "required": true,
				  "type": "string",
				  "format": "int64"
				},
				{
				  "name": "numberPage",
				  "in": "path",
				  "required": true,
				  "type": "string",
				  "format": "int64"
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/delete/{idServer}": {
			"delete": {
			  "operationId": "ServerService_deleteServer",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverDeleteServerResponse"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "idServer",
				  "in": "path",
				  "required": true,
				  "type": "string"
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/detailsServer/{idServer}": {
			"get": {
			  "operationId": "ServerService_detailsServer",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverDetailsServerResponse"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "idServer",
				  "in": "path",
				  "required": true,
				  "type": "string"
				},
				{
				  "name": "serverName",
				  "in": "query",
				  "required": false,
				  "type": "string"
				},
				{
				  "name": "timeIn",
				  "in": "query",
				  "required": false,
				  "type": "string"
				},
				{
				  "name": "timeOut",
				  "in": "query",
				  "required": false,
				  "type": "string"
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			},
			"put": {
			  "operationId": "ServerService_updateServer",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverResponseServer"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "idServer",
				  "in": "path",
				  "required": true,
				  "type": "string"
				},
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"type": "object",
					"properties": {
					  "infoServer": {
						"$ref": "#/definitions/serverServer"
					  }
					}
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/export": {
			"post": {
			  "operationId": "ServerService_export",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverExportResponse"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"$ref": "#/definitions/serverExportRequest"
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  },
		  "/mail": {
			"post": {
			  "operationId": "ServerService_sendMail",
			  "responses": {
				"200": {
				  "description": "A successful response.",
				  "schema": {
					"$ref": "#/definitions/serverMessResponse"
				  }
				},
				"default": {
				  "description": "An unexpected error response.",
				  "schema": {
					"$ref": "#/definitions/rpcStatus"
				  }
				}
			  },
			  "parameters": [
				{
				  "name": "body",
				  "in": "body",
				  "required": true,
				  "schema": {
					"$ref": "#/definitions/serverSendMailRequest"
				  }
				}
			  ],
			  "tags": [
				"ServerService"
			  ]
			}
		  }
		},
		"definitions": {
		  "protobufAny": {
			"type": "object",
			"properties": {
			  "typeUrl": {
				"type": "string"
			  },
			  "value": {
				"type": "string",
				"format": "byte"
			  }
			}
		  },
		  "rpcStatus": {
			"type": "object",
			"properties": {
			  "code": {
				"type": "integer",
				"format": "int32"
			  },
			  "message": {
				"type": "string"
			  },
			  "details": {
				"type": "array",
				"items": {
				  "$ref": "#/definitions/protobufAny"
				}
			  }
			}
		  },
		  "serverChangeStatusRequest": {
			"type": "object",
			"properties": {
			  "timeCheck": {
				"type": "string",
				"format": "int64"
			  }
			}
		  },
		  "serverDeleteServerResponse": {
			"type": "object",
			"properties": {
			  "ok": {
				"type": "boolean"
			  }
			}
		  },
		  "serverDetailsServerResponse": {
			"type": "object",
			"properties": {
			  "statusServer": {
				"type": "boolean"
			  },
			  "status": {
				"type": "array",
				"items": {
				  "$ref": "#/definitions/serverStatusDetail"
				}
			  }
			}
		  },
		  "serverExportRequest": {
			"type": "object",
			"properties": {
			  "page": {
				"type": "boolean"
			  },
			  "numberPage": {
				"type": "string",
				"format": "int64"
			  },
			  "limitPage": {
				"type": "string",
				"format": "int64"
			  }
			}
		  },
		  "serverExportResponse": {
			"type": "object",
			"properties": {
			  "url": {
				"type": "string"
			  }
			}
		  },
		  "serverListServer": {
			"type": "object",
			"properties": {
			  "data": {
				"type": "array",
				"items": {
				  "$ref": "#/definitions/serverServer"
				}
			  }
			}
		  },
		  "serverLoginServer": {
			"type": "object",
			"properties": {
			  "username": {
				"type": "string"
			  },
			  "password": {
				"type": "string"
			  }
			}
		  },
		  "serverMessResponse": {
			"type": "object",
			"properties": {
			  "mess": {
				"type": "string"
			  }
			}
		  },
		  "serverResponseServer": {
			"type": "object",
			"properties": {
			  "idServer": {
				"type": "string"
			  },
			  "data": {
				"$ref": "#/definitions/serverServer"
			  }
			}
		  },
		  "serverResultLogin": {
			"type": "object",
			"properties": {
			  "ok": {
				"type": "boolean"
			  },
			  "accessToken": {
				"type": "string"
			  }
			}
		  },
		  "serverSendMailRequest": {
			"type": "object",
			"properties": {
			  "email": {
				"type": "string"
			  }
			}
		  },
		  "serverServer": {
			"type": "object",
			"properties": {
			  "username": {
				"type": "string"
			  },
			  "serverName": {
				"type": "string"
			  },
			  "ip": {
				"type": "string"
			  },
			  "password": {
				"type": "string"
			  }
			}
		  },
		  "serverStatusDetail": {
			"type": "object",
			"properties": {
			  "statusDt": {
				"type": "boolean"
			  },
			  "time": {
				"type": "string"
			  }
			}
		  }
		}
	  }
	  
	`
)
