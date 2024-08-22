Intel Trust Authority Azure CVM Intel TDX with vTPM Adapter for Go

<p style="font-size: 0.875em;">· 08/22/2024 ·</p>

> [!NOTE]
> Intel® Trust Authority Azure confidential VM (CVM) with Intel TDX and vTPM Adapter for Go is in limited preview status. Details of implementation and usage may change before general availability. Preview features are only available on the Intel Trust Authority pilot environment. Contact your Intel representative for access.


## Usage

Import the **go-aztdx** package into your project to attest an Azure confidential VM with Intel TDX and vTPM. The following import statements includes the **go-connector**, which provides the core functionality for attestation, and **go-tpm**, which provides the TPM adapter for interacting with the vTPM.

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