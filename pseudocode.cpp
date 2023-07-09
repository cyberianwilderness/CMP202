
// Plan
    // User can test how long it takes to break a specific password (or passwords)
    // User inserts the password they wish to test the strength of
    // Have 16 threads (1 per core) picking a word from the list, hashing it and checking a word from the list
    // each thread comparing against the given hash then move on to the next available word in the dictionary
    // It will move on by starting at a certain point in the list
    // If one thread matches the password, all threads to stop working immediately.
