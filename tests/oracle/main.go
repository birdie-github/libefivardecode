// SPDX-License-Identifier: LGPL-2.1-or-later
// Optional independent field oracle for synthetic fixtures.
package main

import (
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"

    efi "github.com/canonical/go-efilib"
)

func run() error {
    if len(os.Args) != 3 {
        return fmt.Errorf("usage: oracle boot|db FILE")
    }
    f, err := os.Open(os.Args[2])
    if err != nil { return err }
    defer f.Close()
    enc := json.NewEncoder(os.Stdout)
    switch os.Args[1] {
    case "boot":
        opt, err := efi.ReadLoadOption(f)
        if err != nil { return err }
        return enc.Encode([]any{opt.Attributes, opt.Description, hex.EncodeToString(opt.OptionalData)})
    case "db":
        db, err := efi.ReadSignatureDatabase(f)
        if err != nil { return err }
        var rows [][]string
        for _, list := range db {
            for _, sig := range list.Signatures {
                rows = append(rows, []string{list.Type.String(), sig.Owner.String(), hex.EncodeToString(sig.Data)})
            }
        }
        return enc.Encode(rows)
    }
    return fmt.Errorf("unknown format")
}

func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
