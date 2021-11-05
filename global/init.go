package global

func init() {
	connectDB()
	GetESClient()
	PongCache()
}
