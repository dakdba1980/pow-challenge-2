Looking at your code, I can see the issue. The error "can't multiply sequence by non-int of type 'str'" is occurring because the `difficulty` parameter is being passed as a string from the command line arguments, but your code is trying to use it in mathematical operations that expect an integer.

Here's the fix - you need to convert the difficulty to an integer when it's received from the server:The key fix is in the `handle_command` method where the POW command is processed. I changed:

```python
difficulty = args[2]  # This was a string
```

to:

```python
difficulty = int(args[2])  # Now properly converted to integer
```

I also fixed a small issue in the `entropy_search` function where `secrets.SystemRandom()` was being initialized with an invalid argument. The `SystemRandom` constructor doesn't accept seed parameters, so I removed that.

The error was occurring because:
1. The difficulty was being passed as a string from the server
2. In various places in the code, the difficulty was being used in mathematical operations like `'0' * difficulty` and `16 ** difficulty`
3. When difficulty is a string, these operations fail

Now the difficulty is properly converted to an integer when received from the server, and all subsequent operations should work correctly.

## Usage:

```bash
# Basic usage
python optimized_tls_client_v7.py --cert client.crt --key client.key

# With custom host/port
python optimized_tls_client_v7.py --host 18.202.148.130 --port 8083 --cert client.crt --key client.key
```