# User Service

## Session & Token

- Session indicates a specific connection between user's browser/device and the server.
  - Can be stored as a set owns by the user. When we need to revoke some of the sessions, removing the session from the set will do the job.
- Token is a string that can be used to authenticate the user. In services, it can be decrypted to get the user Info.
  - Token changes when user updates their info or roles.
  - For safety, token should be have a short expiration time, e.g. 1 hour, we refresh it when it's about to expire.
