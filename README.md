
# prct - Process Relationship and Control Tool

`prct` is a Linux-based command-line tool written in C that analyzes the process tree rooted at a specified PID. It provides a variety of features for inspecting process relationships, identifying zombie or orphaned processes, and controlling process states using system signals.

---

## 📦 Features

- 🧵 **Process Tree Traversal**
  - Checks if a process is a descendant of another.
  - Lists direct and indirect descendants.

- 🔍 **Information Retrieval Options**
  - `-dc`: Count all defunct descendants.
  - `-df`: List all defunct descendants.
  - `-id`: List immediate descendants.
  - `-ds`: List non-immediate descendants.
  - `-gc`: List all grandchildren.
  - `-lg`: List all siblings.
  - `-lz`: List all defunct siblings.
  - `-op`: List all orphaned descendants.
  - `-ps`: Print process status (Defunct / Not Defunct).
  - `-os`: Print process status (Orphan / Not Orphan).

- 🛠️ **Signal Controls**
  - `-sk`: Send SIGKILL to all descendants.
  - `-st`: Send SIGSTOP to all descendants.
  - `-sc`: Send SIGCONT to all paused descendants.
  - `-pz`: Kill the parent of all zombie processes under a given process.

---

## 🧪 Usage

```bash
./prct <root_process_id> <process_id> [OPTION]
```

### Examples

```bash
./prct 1004 1005 -op   # Lists orphan descendants of PID 1005 under root 1004
./prct 2000 2001 -df   # Lists defunct descendants of 2001 under root 2000
./prct 3000 3001 -gc   # Lists grandchildren of 3001
./prct 4000 4001 -sk   # Sends SIGKILL to all descendants of 4001 under root 4000
```

If no option is provided, the program checks whether the process ID belongs to the tree rooted at the root process.

---

## ⚙️ Build Instructions

```bash
gcc -o prct prct.c
```

> Note: Must be run on **Linux** systems. Not compatible with macOS as it lacks the `/proc` filesystem.

---

## 📁 Dependencies

- Linux `/proc` filesystem
- Standard C libraries

---

## 🚨 Permissions

Some operations (like sending signals to system processes) may require `sudo` access.

```bash
sudo ./prct 1 1234 -sk
```

---

## 📎 License

MIT License (or specify your preferred license)

---

## 👨‍💻 Author

- Saima Khatoon
- Developed as part of a systems programming Course.
