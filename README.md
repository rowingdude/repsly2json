# repsly2json
This is basically step 1 of the process of importing these data to PostgreSQL directly as JSON objects.

This project will be run in conjunction with Repsly2CSV.

We will enable users to have a direct path from Repsly servers to a PostgreSQL (or other) database where all data can be queried for analysis.

`r2j_pg` file includes all of the original plus a few fixups like debugging output and more helpful output in general.

      $ ./repsly2json 
        Processed pricelistsItems     Failed Failed or returned no data
        Processed pricelists          OK
        Processed representatives     OK
        Processed documentTypes       OK
        Processed clientnotes         [3970/100] ID: xxxxxxxxxx

