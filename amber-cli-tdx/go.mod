module github.com/intel/amber/v1/client/tdx-cli

require (
	github.com/google/uuid v1.3.0
	github.com/intel/amber/v1/client v0.0.0
	github.com/intel/amber/v1/client/tdx v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.6.1
	github.com/spf13/viper v1.14.0
	github.com/gorilla/mux v1.8.0
)

replace github.com/intel/amber/v1/client => ../go-client
replace github.com/intel/amber/v1/client/tdx => ../go-tdx

require (
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.5 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	golang.org/x/sys v0.0.0-20220908164124-27713097b956 // indirect
	golang.org/x/text v0.4.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

