# Dock.io client webhook

## References

- [Dock.io gateway.rst](https://github.com/getdock/public-docs/blob/master/gateway.rst)
- [partner-integration-by-example.sh](https://github.com/getdock/public-docs/blob/master/partner-integration-by-example.sh)

## Example responses


```json
{
    "$createdAt": "2018-10-19T02:40:57",
    "$data": {
        "email": "gustavo@canya.com"
    },
    "$originAddress": "bad062f012c29a23fcb759ad1d6f73dbf788002e",
    "$recipientAddress": "e41106e9ae2a3ffecc37f032901d9bc8fc993b59",
    "$schema": "https://getdock.github.io/schemas/email.json"
}
```

```json
{
    "$createdAt": "2018-10-19T02:40:57",
    "$data": {
        "avatar": null,
        "firstName": "Gustavo",
        "lastName": "Ibarra"
    },
    "$originAddress": "bad062f012c29a23fcb759ad1d6f73dbf788002e",
    "$recipientAddress": "e41106e9ae2a3ffecc37f032901d9bc8fc993b59",
    "$schema": "https://getdock.github.io/schemas/basicUserProfile.json"
}
```