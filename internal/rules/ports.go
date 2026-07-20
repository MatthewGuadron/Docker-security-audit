package rules

var SensitivePorts = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	3389:  "RDP",
	5900:  "VNC",
}
