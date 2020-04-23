# aws_client_id_secret_hash
Creates aws-usable (Amazon Web Services) hash from clientid clientsecret and username.<br />
A config file is automatically created the first time the utility is run.<br />
This is typically used in conjunction with the aws suite of command line utilities.<br />
E.G.:
`aws cognito-idp resend-confirmation-code --client-id thisisclientid --secret-hash valuefromthisutility --username 0000-0000-someuser`
