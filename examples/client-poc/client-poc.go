// client-poc.go
package main

import (
	"fmt"

	"github.com/mtesauro/tfclient"
)

func main() {
	fmt.Println("POC ThreadFix Go Client")
	// First Create a client for talking to the API
	tfc := tfclient.CreateClient()
	fmt.Printf("tfc is %+v \n", tfc)
	// Before searching you must setup a default Search Struct
	srch := tfclient.CreateSearchStruct()
	// Restrict default search to only 4 results
	tfclient.NumSearchResults(&srch, 4)
	// Send the search query to TF
	vulns := tfclient.VulnSearch(tfc, &srch)
	// Create a search struct and load it with the search with just conducted
	var search tfclient.SrchResp
	tfclient.MakeSearchStruct(&search, vulns)
	fmt.Printf("search is %+v \n", search)

}
