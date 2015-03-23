// client-poc.go
package main

import (
	"fmt"
	"github.com/mtesauro/tfclient"
	"os"
)

func main() {
	fmt.Println("POC ThreadFix Go Client")
	// First Create a client for talking to the API
	tfc, err := tfclient.CreateClient()
	if err != nil {
		fmt.Print(err)
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
	//fmt.Printf("\nvulns is %+v\n\n", vulns)
	//os.Exit(0)
	tfclient.MakeSearchStruct(&search, vulns)
	fmt.Printf("\nSearch results are:\n %+v \n\n", search)

}
