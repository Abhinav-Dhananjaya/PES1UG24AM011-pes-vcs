# Building PES-VCS — A Version Control System from Scratch

**Objective:** Build a local version control system that tracks file changes, stores snapshots efficiently, and supports commit history. Every component maps directly to operating system and filesystem concepts.

**Platform:** Ubuntu 22.04

---

## Getting Started

### Prerequisites

```bash
sudo apt update && sudo apt install -y gcc build-essential libssl-dev
```

### Using This Repository

This is a **template repository**. Do **not** fork it.

1. Click **"Use this template"** → **"Create a new repository"** on GitHub
2. Name your repository (e.g., `SRN-pes-vcs`) and set it to **public**. Replace `SRN` with your actual SRN, e.g., `PESXUG24CSYYY-pes-vcs`
3. Clone this repository to your local machine and do all your lab work inside this directory.
4.  **Important:** Remember to commit frequently as you progress. You are required to have a minimum of 5 detailed commits per phase. Refer to [Submission Requirements](#submission-requirements) for more details.
5. Clone your new repository and start working

The repository contains skeleton source files with `// TODO` markers where you need to write code. Functions marked `// PROVIDED` are complete — do not modify them.

### Building

```bash
make          # Build the pes binary
make all      # Build pes + test binaries
make clean    # Remove all build artifacts
```

### Author Configuration

PES-VCS reads the author name from the `PES_AUTHOR` environment variable:

```bash
export PES_AUTHOR="Your Name <PESXUG24CS042>"
```

If unset, it defaults to `"PES User <pes@localhost>"`.

### File Inventory

| File               | Role                                 | Your Task                                          |
| ------------------ | ------------------------------------ | -------------------------------------------------- |
| `pes.h`            | Core data structures and constants   | Do not modify                                      |
| `object.c`         | Content-addressable object store     | Implement `object_write`, `object_read`            |
| `tree.h`           | Tree object interface                | Do not modify                                      |
| `tree.c`           | Tree serialization and construction  | Implement `tree_from_index`                        |
| `index.h`          | Staging area interface               | Do not modify                                      |
| `index.c`          | Staging area (text-based index file) | Implement `index_load`, `index_save`, `index_add`  |
| `commit.h`         | Commit object interface              | Do not modify                                      |
| `commit.c`         | Commit creation and history          | Implement `commit_create`                          |
| `pes.c`            | CLI entry point and command dispatch | Do not modify                                      |
| `test_objects.c`   | Phase 1 test program                 | Do not modify                                      |
| `test_tree.c`      | Phase 2 test program                 | Do not modify                                      |
| `test_sequence.sh` | End-to-end integration test          | Do not modify                                      |
| `Makefile`         | Build system                         | Do not modify                                      |

---

## Understanding Git: What You're Building

Before writing code, understand how Git works under the hood. Git is a content-addressable filesystem with a few clever data structures on top. Everything in this lab is based on Git's real design.

### The Big Picture

When you run `git commit`, Git doesn't store "changes" or "diffs." It stores **complete snapshots** of your entire project. Git uses two tricks to make this efficient:

1. **Content-addressable storage:** Every file is stored by the SHA hash of its contents. Same content = same hash = stored only once.
2. **Tree structures:** Directories are stored as "tree" objects that point to file contents, so unchanged files are just pointers to existing data.

```
Your project at commit A:          Your project at commit B:
                                   (only README changed)

    root/                              root/
    ├── README.md  ─────┐              ├── README.md  ─────┐
    ├── src/            │              ├── src/            │
    │   └── main.c ─────┼─┐            │   └── main.c ─────┼─┐
    └── Makefile ───────┼─┼─┐          └── Makefile ───────┼─┼─┐
                        │ │ │                              │ │ │
                        ▼ ▼ ▼                              ▼ ▼ ▼
    Object Store:       ┌─────────────────────────────────────────────┐
                        │  a1b2c3 (README v1)    ← only this is new   │
                        │  d4e5f6 (README v2)                         │
                        │  789abc (main.c)       ← shared by both!    │
                        │  fedcba (Makefile)     ← shared by both!    │
                        └─────────────────────────────────────────────┘
```

### The Three Object Types

#### 1. Blob (Binary Large Object)

A blob is just file contents. No filename, no permissions — just the raw bytes.

```
blob 16\0Hello, World!\n
     ↑    ↑
     │    └── The actual file content
     └─────── Size in bytes
```

The blob is stored at a path determined by its SHA-256 hash. If two files have identical contents, they share one blob.

#### 2. Tree

A tree represents a directory. It's a list of entries, each pointing to a blob (file) or another tree (subdirectory).

```
100644 blob a1b2c3d4... README.md
100755 blob e5f6a7b8... build.sh        ← executable file
040000 tree 9c0d1e2f... src             ← subdirectory
       ↑    ↑           ↑
       │    │           └── name
       │    └── hash of the object
       └─────── mode (permissions + type)
```

Mode values:
- `100644` — regular file, not executable
- `100755` — regular file, executable
- `040000` — directory (tree)

#### 3. Commit

A commit ties everything together. It points to a tree (the project snapshot) and contains metadata.

```
tree 9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d
parent a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
author Alice <alice@example.com> 1699900000
committer Alice <alice@example.com> 1699900000

Add new feature
```

The parent pointer creates a linked list of history:

```
    C3 ──────► C2 ──────► C1 ──────► (no parent)
    │          │          │
    ▼          ▼          ▼
  Tree3      Tree2      Tree1
```

### How Objects Connect

```
                    ┌─────────────────────────────────┐
                    │           COMMIT                │
                    │  tree: 7a3f...                  │
                    │  parent: 4b2e...                │
                    │  author: Alice                  │
                    │  message: "Add feature"         │
                    └─────────────┬───────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────┐
                    │         TREE (root)             │
                    │  100644 blob f1a2... README.md  │
                    │  040000 tree 8b3c... src        │
                    │  100644 blob 9d4e... Makefile   │
                    └──────┬──────────┬───────────────┘
                           │          │
              ┌────────────┘          └────────────┐
              ▼                                    ▼
┌─────────────────────────┐          ┌─────────────────────────┐
│      TREE (src)         │          │     BLOB (README.md)    │
│ 100644 blob a5f6 main.c │          │  # My Project           │
└───────────┬─────────────┘          └─────────────────────────┘
            ▼
       ┌────────┐
       │ BLOB   │
       │main.c  │
       └────────┘
```

### References and HEAD

References are files that map human-readable names to commit hashes:

```
.pes/
├── HEAD                    # "ref: refs/heads/main"
└── refs/
    └── heads/
        └── main            # Contains: a1b2c3d4e5f6...
```

**HEAD** points to a branch name. The branch file contains the latest commit hash. When you commit:

1. Git creates the new commit object (pointing to parent)
2. Updates the branch file to contain the new commit's hash
3. HEAD still points to the branch, so it "follows" automatically

```
Before commit:                    After commit:

HEAD ─► main ─► C2 ─► C1         HEAD ─► main ─► C3 ─► C2 ─► C1
```

### The Index (Staging Area)

The index is the "preparation area" for the next commit. It tracks which files are staged.

```
Working Directory          Index               Repository (HEAD)
─────────────────         ─────────           ─────────────────
README.md (modified) ──── pes add ──► README.md (staged)
src/main.c                            src/main.c          ──► Last commit's
Makefile                               Makefile                snapshot
```

The workflow:

1. `pes add file.txt` → computes blob hash, stores blob, updates index
2. `pes commit -m "msg"` → builds tree from index, creates commit, updates branch ref

### Content-Addressable Storage

Objects are named by their content's hash:

```python
# Pseudocode
def store_object(content):
    hash = sha256(content)
    path = f".pes/objects/{hash[0:2]}/{hash[2:]}"
    write_file(path, content)
    return hash
```

This gives us:
- **Deduplication:** Identical files stored once
- **Integrity:** Hash verifies data isn't corrupted
- **Immutability:** Changing content = different hash = different object

Objects are sharded by the first two hex characters to avoid huge directories:

```
.pes/objects/
├── 2f/
│   └── 8a3b5c7d9e...
├── a1/
│   ├── 9c4e6f8a0b...
│   └── b2d4f6a8c0...
└── ff/
    └── 1234567890...
```

### Exploring a Real Git Repository

You can inspect Git's internals yourself:

```bash
mkdir test-repo && cd test-repo && git init
echo "Hello" > hello.txt
git add hello.txt && git commit -m "First commit"

find .git/objects -type f          # See stored objects
git cat-file -t <hash>            # Show type: blob, tree, or commit
git cat-file -p <hash>            # Show contents
cat .git/HEAD                     # See what HEAD points to
cat .git/refs/heads/main          # See branch pointer
```

---

## What You'll Build

PES-VCS implements five commands across four phases:

```
pes init              Create .pes/ repository structure
pes add <file>...     Stage files (hash + update index)
pes status            Show modified/staged/untracked files
pes commit -m <msg>   Create commit from staged files
pes log               Walk and display commit history
```

The `.pes/` directory structure:

```
my_project/
├── .pes/
│   ├── objects/          # Content-addressable blob/tree/commit storage
│   │   ├── 2f/
│   │   │   └── 8a3b...   # Sharded by first 2 hex chars of hash
│   │   └── a1/
│   │       └── 9c4e...
│   ├── refs/
│   │   └── heads/
│   │       └── main      # Branch pointer (file containing commit hash)
│   ├── index             # Staging area (text file)
│   └── HEAD              # Current branch reference
└── (working directory files)
```

### Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│                      WORKING DIRECTORY                        │
│                  (actual files you edit)                       │
└───────────────────────────────────────────────────────────────┘
                              │
                        pes add <file>
                              ▼
┌───────────────────────────────────────────────────────────────┐
│                           INDEX                               │
│                (staged changes, ready to commit)              │
│                100644 a1b2c3... src/main.c                    │
└───────────────────────────────────────────────────────────────┘
                              │
                       pes commit -m "msg"
                              ▼
┌───────────────────────────────────────────────────────────────┐
│                       OBJECT STORE                            │
│  ┌───────┐    ┌───────┐    ┌────────┐                         │
│  │ BLOB  │◄───│ TREE  │◄───│ COMMIT │                         │
│  │(file) │    │(dir)  │    │(snap)  │                         │
│  └───────┘    └───────┘    └────────┘                         │
│  Stored at: .pes/objects/XX/YYY...                            │
└───────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────┐
│                           REFS                                │
│       .pes/refs/heads/main  →  commit hash                    │
│       .pes/HEAD             →  "ref: refs/heads/main"         │
└───────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Object Storage Foundation

**Filesystem Concepts:** Content-addressable storage, directory sharding, atomic writes, hashing for integrity

**Files:** `pes.h` (read), `object.c` (implement `object_write` and `object_read`)

### What to Implement

Open `object.c`. Two functions are marked `// TODO`:

1. **`object_write`** — Stores data in the object store.
   - Prepends a type header (`"blob <size>\0"`, `"tree <size>\0"`, or `"commit <size>\0"`)
   - Computes SHA-256 of the full object (header + data)
   - Writes atomically using the temp-file-then-rename pattern
   - Shards into subdirectories by first 2 hex chars of hash

2. **`object_read`** — Retrieves and verifies data from the object store.
   - Reads the file, parses the header to extract type and size
   - **Verifies integrity** by recomputing the hash and comparing to the filename
   - Returns the data portion (after the `\0`)

Read the detailed step-by-step comments in `object.c` before starting.

### Testing

```bash
make test_objects
./test_objects
```

The test program verifies:
- Blob storage and retrieval (write, read back, compare)
- Deduplication (same content → same hash → stored once)
- Integrity checking (detects corrupted objects)

**📸 Screenshot 1A:** Output of `./test_objects` showing all tests passing.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/1b5c60eb-173d-41bf-ab9c-efc66f223baf" />


**📸 Screenshot 1B:** `find .pes/objects -type f` showing the sharded directory structure.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/e6700c27-0837-4091-8d47-84ac0a48e743" />


---

## Phase 2: Tree Objects

**Filesystem Concepts:** Directory representation, recursive structures, file modes and permissions

**Files:** `tree.h` (read), `tree.c` (implement all TODO functions)

### What to Implement

Open `tree.c`. Implement the function marked `// TODO`:

1. **`tree_from_index`** — Builds a tree hierarchy from the index.
   - Handles nested paths: `"src/main.c"` must create a `src` subtree
   - This is what `pes commit` uses to create the snapshot
   - Writes all tree objects to the object store and returns the root hash

### Testing

```bash
make test_tree
./test_tree
```

The test program verifies:
- Serialize → parse roundtrip preserves entries, modes, and hashes
- Deterministic serialization (same entries in any order → identical output)

**📸 Screenshot 2A:** Output of `./test_tree` showing all tests passing.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/3e9303a8-b139-4d2f-bd73-6fda070df41c" />


**📸 Screenshot 2B:** Pick a tree object from `find .pes/objects -type f` and run `xxd .pes/objects/XX/YYY... | head -20` to show the raw binary format.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/3de5c285-f16f-48d4-a25a-3f30328c1b72" />

---

## Phase 3: The Index (Staging Area)

**Filesystem Concepts:** File format design, atomic writes, change detection using metadata

**Files:** `index.h` (read), `index.c` (implement all TODO functions)

### What to Implement

Open `index.c`. Three functions are marked `// TODO`:

1. **`index_load`** — Reads the text-based `.pes/index` file into an `Index` struct.
   - If the file doesn't exist, initializes an empty index (this is not an error)
   - Parses each line: `<mode> <hash-hex> <mtime> <size> <path>`

2. **`index_save`** — Writes the index atomically (temp file + rename).
   - Sorts entries by path before writing
   - Uses `fsync()` on the temp file before renaming

3. **`index_add`** — Stages a file: reads it, writes blob to object store, updates index entry.
   - Use the provided `index_find` to check for an existing entry

`index_find` , `index_status` and `index_remove` are already implemented for you — read them to understand the index data structure before starting.

#### Expected Output of `pes status`

```
Staged changes:
  staged:     hello.txt
  staged:     src/main.c

Unstaged changes:
  modified:   README.md
  deleted:    old_file.txt

Untracked files:
  untracked:  notes.txt
```

If a section has no entries, print the header followed by `(nothing to show)`.

### Testing

```bash
make pes
./pes init
echo "hello" > file1.txt
echo "world" > file2.txt
./pes add file1.txt file2.txt
./pes status
cat .pes/index    # Human-readable text format
```

**📸 Screenshot 3A:** Run `./pes init`, `./pes add file1.txt file2.txt`, `./pes status` — show the output.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/df95e26e-5556-444c-bfd6-95da18a40583" />


**📸 Screenshot 3B:** `cat .pes/index` showing the text-format index with your entries.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/d9ceba28-b12d-486e-ab9c-563977005706" />


---

## Phase 4: Commits and History

**Filesystem Concepts:** Linked structures on disk, reference files, atomic pointer updates

**Files:** `commit.h` (read), `commit.c` (implement all TODO functions)

### What to Implement

Open `commit.c`. One function is marked `// TODO`:

1. **`commit_create`** — The main commit function:
   - Builds a tree from the index using `tree_from_index()` (**not** from the working directory — commits snapshot the staged state)
   - Reads current HEAD as the parent (may not exist for first commit)
   - Gets the author string from `pes_author()` (defined in `pes.h`)
   - Writes the commit object, then updates HEAD

`commit_parse`, `commit_serialize`, `commit_walk`, `head_read`, and `head_update` are already implemented — read them to understand the commit format before writing `commit_create`.

The commit text format is specified in the comment at the top of `commit.c`.

### Testing

```bash
./pes init
echo "Hello" > hello.txt
./pes add hello.txt
./pes commit -m "Initial commit"

echo "World" >> hello.txt
./pes add hello.txt
./pes commit -m "Add world"

echo "Goodbye" > bye.txt
./pes add bye.txt
./pes commit -m "Add farewell"

./pes log
```

You can also run the full integration test:

```bash
make test-integration
```

**📸 Screenshot 4A:** Output of `./pes log` showing three commits with hashes, authors, timestamps, and messages.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/b5bd7044-35c9-4416-9bf1-cdcb2ca66d21" />


**📸 Screenshot 4B:** `find .pes -type f | sort` showing object store growth after three commits.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/b7fcd848-3269-4784-80bd-411cbce3b872" />


**📸 Screenshot 4C:** `cat .pes/refs/heads/main` and `cat .pes/HEAD` showing the reference chain.
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/6759621b-866f-4178-a324-08f47cb9d63c" />

INTEGRATION TEST SCREENSHOT :<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/039ef3a9-6149-4191-9342-e99d39e6935c" />

---

## Phase 5 & 6: Analysis-Only Questions

The following questions cover filesystem concepts beyond the implementation scope of this lab. Answer them in writing — no code required.

### Branching and Checkout

**Q5.1:** A branch in Git is just a file in `.git/refs/heads/` containing a commit hash. Creating a branch is creating a file. Given this, how would you implement `pes checkout <branch>` — what files need to change in `.pes/`, and what must happen to the working directory? What makes this operation complex?
A:A branch is just a file in .pes/refs/heads/ containing a commit hash. To implement pes checkout <branch>:
Files that change in .pes/:
•	.pes/HEAD is updated to contain ref: refs/heads/<branch>
•	.pes/index is rebuilt to reflect the target branch's tree contents
What happens to the working directory:
1.	Read the target branch file to get the commit hash
2.	Read the commit object to get the root tree hash
3.	Recursively walk all tree objects
4.	For each blob entry, read the file content from the object store and write it to the working directory path
5.	Delete any files that exist in the current branch but not in the target branch
What makes it complex:
•	Three things must be updated together: working directory, index, and HEAD. A crash midway leaves the repo in a corrupt state
•	Nested directories must be created if they don't exist
•	Files present in the current branch but absent in the target must be deleted
•	Conflicts with uncommitted local changes must be detected and refused before any changes are made


**Q5.2:** When switching branches, the working directory must be updated to match the target branch's tree. If the user has uncommitted changes to a tracked file, and that file differs between branches, checkout must refuse. Describe how you would detect this "dirty working directory" conflict using only the index and the object store.

A: Before switching branches, for each file tracked in the current index:
1.	Check for unstaged changes: Use stat() on the file and compare mtime and size against the index metadata. If they differ, the file has been modified in the working directory since it was staged.
2.	Check for staged but uncommitted changes: Read the HEAD commit's tree object and compare each blob hash in the tree against the corresponding hash in the index. If they differ, the file has been staged but not yet committed.
3.	Cross-reference with target branch: Read the target branch's commit tree and check if the conflicting file differs between the current HEAD tree and the target tree.
4.	Refuse checkout if a file has local modifications (staged or unstaged) AND that file differs between the two branches. Print an error like: error: Your local changes to 'file.txt' would be overwritten by checkout
This approach avoids re-hashing file contents entirely by using metadata as a fast approximation, exactly as Git does internally with its index cache.

**Q5.3:** "Detached HEAD" means HEAD contains a commit hash directly instead of a branch reference. What happens if you make commits in this state? How could a user recover those commits?

A: What happens: In detached HEAD state, .pes/HEAD contains a raw commit hash instead of ref: refs/heads/main. When you make new commits, the HEAD file is updated to point to each new commit directly. However, no branch file in .pes/refs/heads/ is ever updated. Once you switch to another branch, the HEAD pointer moves away and no named reference points to those commits anymore. They become unreachable orphans in the object store.
How to recover:
1.	Before switching away, note the commit hash shown by ./pes log or stored in .pes/HEAD
2.	Create a new branch manually by writing that hash to a new branch file:
bash
   echo "<commit-hash>" > .pes/refs/heads/recovery-branch
3.	Then checkout that branch normally to resume work from those commits
If the hash was not saved and GC has not run yet, the commit objects still exist in .pes/objects/. A user could manually scan all objects, identify commit objects by their header format, and reconstruct the chain to find the lost commits.


### Garbage Collection and Space Reclamation

**Q6.1:** Over time, the object store accumulates unreachable objects — blobs, trees, or commits that no branch points to (directly or transitively). Describe an algorithm to find and delete these objects. What data structure would you use to track "reachable" hashes efficiently? For a repository with 100,000 commits and 50 branches, estimate how many objects you'd need to visit.
A: Algorithm — Mark and Sweep:
Mark Phase:
1.	Start from every branch file in .pes/refs/heads/
2.	For each branch, read the commit hash and add it to a reachable set
3.	Read the commit object — mark its tree hash as reachable
4.	Recursively walk the tree: for every entry, mark blob hashes and subtree hashes as reachable
5.	Follow the parent pointer of each commit and repeat steps 3-5 until reaching a commit with no parent
6.	Repeat for all 50 branches
Sweep Phase:
1.	Walk every file under .pes/objects/ using directory traversal
2.	Reconstruct each object's hash from its directory name + filename
3.	If the hash is NOT in the reachable set, delete the file
Data Structure: A hash set (implemented as a hash table or sorted array of 32-byte hashes) is ideal. Lookup is O(1) average for hash tables. Membership checks are fast and memory efficient.
Estimation for 100,000 commits and 50 branches:
•	Each commit references: 1 commit object + 1 root tree + ~5 subtrees + ~20 blobs = ~27 objects per commit
•	Total reachable objects ≈ 100,000 × 27 = 2,700,000 objects to visit during mark phase
•	Reachable set memory ≈ 2,700,000 × 32 bytes = ~86MB — manageable on any modern system


**Q6.2:** Why is it dangerous to run garbage collection concurrently with a commit operation? Describe a race condition where GC could delete an object that a concurrent commit is about to reference. How does Git's real GC avoid this?
A: The Race Condition:
1.	A commit operation begins and writes a new blob object to .pes/objects/. At this point, no tree or commit object references this blob yet.
2.	GC runs concurrently. It traverses all reachable objects starting from existing branch references. Since the blob has not yet been referenced by any tree or commit, GC marks it as unreachable and deletes it.
3.	The commit operation resumes and tries to write a tree object that references the now-deleted blob. The repository is now permanently corrupt — the tree points to a blob that no longer exists.
How Git avoids this:
1.	Grace period: Git's GC never deletes objects newer than 2 weeks old, regardless of reachability. This gives all in-progress operations enough time to complete and create references to new objects before GC can touch them.
2.	Lock files: Git writes a gc.pid lock file before GC starts. If another process sees this file, it knows GC is running and can wait or abort.
3.	Ref-log protection: Git maintains a reflog that records recent HEAD movements. GC treats all objects reachable from the reflog as protected, even if no current branch points to them.
4.	Atomic reference updates: Commit operations update branch refs atomically using the temp-file-then-rename pattern. GC respects in-progress ref updates by checking for .lock files on ref files before scanning.


---

## Submission Checklist

### Screenshots Required

| Phase | ID  | What to Capture                                                 |
| ----- | --- | --------------------------------------------------------------- |
| 1     | 1A  | `./test_objects` output showing all tests passing               |
| 1     | 1B  | `find .pes/objects -type f` showing sharded directory structure |
| 2     | 2A  | `./test_tree` output showing all tests passing                  |
| 2     | 2B  | `xxd` of a raw tree object (first 20 lines)                    |
| 3     | 3A  | `pes init` → `pes add` → `pes status` sequence                 |
| 3     | 3B  | `cat .pes/index` showing the text-format index                  |
| 4     | 4A  | `pes log` output with three commits                            |
| 4     | 4B  | `find .pes -type f \| sort` showing object growth              |
| 4     | 4C  | `cat .pes/refs/heads/main` and `cat .pes/HEAD`                 |
| Final | --  | Full integration test (`make test-integration`)                 |

### Code Files Required (5 files)

| File           | Description                              |
| -------------- | ---------------------------------------- |
| `object.c`     | Object store implementation              |
| `tree.c`       | Tree serialization and construction      |
| `index.c`      | Staging area implementation              |
| `commit.c`     | Commit creation and history walking      |

### Analysis Questions (written answers)

| Section                   | Questions        |
| ------------------------- | ---------------- |
| Branching (analysis-only) | Q5.1, Q5.2, Q5.3 |
| GC (analysis-only)        | Q6.1, Q6.2       |

-----------

## Submission Requirements

**1. GitHub Repository**
* You must submit the link to your GitHub repository via the official submission link (which will be shared by your respective faculty).
* The repository must strictly maintain the directory structure you built throughout this lab.
* Ensure your github repository is made `public`

**2. Lab Report**
* Your report, containing all required **screenshots** and answers to the **analysis questions**, must be placed at the **root** of your repository directory.
* The report must be submitted as either a PDF (`report.pdf`) or a Markdown file (`README.md`).

**3. Commit History (Graded Requirement)**
* **Minimum Requirement:** You must have a minimum of **5 commits per phase** with appropriate commit messages. Submitting fewer than 5 commits for any given phase will result in a deduction of marks.
* **Best Practices:** We highly prefer more than 5 detailed commits per phase. Granular commits that clearly show the delta in code block changes allow us to verify your step-by-step understanding of the concepts and prevent penalties <3

---

## Further Reading

- **Git Internals** (Pro Git book): https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain
- **Git from the inside out**: https://codewords.recurse.com/issues/two/git-from-the-inside-out
- **The Git Parable**: https://tom.preston-werner.com/2009/05/19/the-git-parable.html
