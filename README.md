The Dagger (XDAG) cryptocurrency
================================

- Official site: http://xdag.me
- Main net is launched January 5, 2018 at 22:45 GMT. 


Principles:
----------

- Directed acyclic graph (DAG), not blockchain
- Block = transaction = address
- Original main chain idea
- Mineable, no premine, no ICO
- Mining new money every 64 seconds


Install and run (Linux):
-----------------------

- Install dependencies:

		$ sudo dnf install git gcc openssl-devel
		or
		$ sudo apt-get install git gcc libssl-dev

- Clone from the git repository:

        $ git clone http://xdag.me/xdag.git

- Make:

        $ cd xdag/cheatcoin
        $ make

- Run, for example, the miner with 2 CPU mining threads, in daemon mode, connected to the pool xdag.me:13654

        $ ./xdag -m 2 -d xdag.me:13654
        Enter random characters: [enter]

- Run terminal connected to the daemon in the same folder:

        $ xdag -i
        xdag> help
        [see help]

- See if you are connected to the pool:

        xdag> state
        [see state]

- See your balance:

        xdag> balance
        [balance]

- See your address:

        xdag> account
        [address]

- Transfer funds to another address:

        xdag> xfer [amount] [address]


Main chain idea:
---------------

Every block in DAG has up to 15 links to another blocks (inputs and outputs).
Block B is _referenced_ by another block A if we can reach B from A by following the links.
_Chain_ is a sequence of blocks each of which is referenced by the previous block.
Chain is called _distinct_ if every its block belongs to separate 64-seconds interval.
_Difficulty_of_block_ is 1/hash where _hash_ is sha256(sha256(block)) regarded as little-endian number.
_Difficulty_of_chain_ is sum of difficulties of blocks.
_Main_chain_ is the distinct chain with maximum difficulty.
Blocks in main chain are called _main_blocks_.

Daggers are mined in every main block.
For first 4 years 1024 XDAG are mined in each main block.
For second 4 years - 512 XDAG, and so on.
So, maximum XDAG supply is approximately power(2,32).
Each dagger is equal to power(2,32) cheatoshino.
Transaction is _valid_ if it is referenced by a main block.
Valid transactions are strictly ordered depending on main chain and links order.
Double spending is prohibited because only first concurrent transaction (by this order) is applied.


Structure of block:
------------------

Each block has fixed size 512 bytes.
Block consists of 16 fields each of whish has length 32 bytes.
Field 0 is header, it consists of 4 quadwords:
- transport-layer header
- types of all 16 fields, 4 bits for one type
- timestamp of the block, in seconds from Unix era * 1024
- block fee in cheatoshi

Types of fields:

0. nonce
1. header
2. transaction input: 24 lower bytes of block hash and 8 bytes of input amount
3. transaction output, structure is the same as input
4. half of block signature; ECDSA number r or s; digest for signature is hash of (block concate public key)
5. half of output signature; only owner of this key can use this block as input
6. public key (x) with even y
7. public key with odd y
8. ... 15. are reserved for future usage.


Transport layer:
---------------

The dnet network is used as transport layer.


Updates:
---------------

Replacement SHA256 transform code from openssl project,
modified by true ( XDAG rvKaJSbP9DE6sg6XetYtSpaK+2aDbUq8 )

- 50-150% speedup on Intel Core series post-Nehalem
- 50-100% speedup on AMD Heavy Equipment cores
- 400-500% speedup on Ryzen
- Better use of threads than reference implementation

Heat output is increased with the fast version, so you may want to continue using the old implementation on devices with poor cooling (notebooks, etc).
