// client-poc.go
package main

import (
	"fmt"
	"github.com/mtesauro/tfclient"
	"os"
	"strings"
)

func main() {
	fmt.Println("POC ThreadFix Go Client\n")

	// First Create a client for talking to the API
	tfc, err := tfclient.CreateClient()
	if err != nil {
		fmt.Print(err)
		if strings.Contains(err.Error(), "Unable to find config file") {
			tfclient.CreateEmptyConfig()
			fmt.Println("An default config file named tfclient.config was created in the current directory")
			fmt.Println("Please update that file with the values for your ThreadFix installation\n")
		}
		os.Exit(1)
	}
	fmt.Printf("\ntfc - the client connection is: \n %+v \n", tfc)

	// Before searching you must setup a default Search Struct
	srch := tfclient.CreateSearchStruct()

	// Restrict default search to only 4 results
	tfclient.NumSearchResults(&srch, 4)

	// Send the search query to TF
	vulns, err := tfclient.VulnSearch(tfc, &srch)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	// Create a search struct and load it with the search with just conducted
	var search tfclient.SrchResp
	tfclient.MakeSearchStruct(&search, vulns)

	// Print the search struct
	fmt.Printf("\nSearch results are:\n %+v \n\n", search)

}
