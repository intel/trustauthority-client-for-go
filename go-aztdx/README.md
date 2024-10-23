Intel Trust Authority Azure CVM Intel TDX for Go

<p style="font-size: 0.875em;">· 08/22/2024 ·</p>


## Usage

Import the **go-aztdx** package into your project to collect TDX evidence from an Azure confidential VM. The following import statements includes the **go-connector**, which provides the core functionality for attestation, and **go-tpm**, which is used to collect TDX evidence from Azure's vTPM.

```go

import(
	"github.com/intel/trustauthority-client/aztdx"
	"github.com/intel/trustauthority-client/go-connector"
	"github.com/intel/trustauthority-client/tpm"
)
```


## Code of Conduct and Contributing

See the [CONTRIBUTING](../CONTRIBUTING.md) file for information on how to contribute to this project. The project follows the [ Code of Conduct](../CODE_OF_CONDUCT.md).

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.

<br><br>
---
**\*** Other names and brands may be claimed as the property of others.