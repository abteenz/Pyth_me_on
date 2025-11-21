def validate_password(password):
    errors = []  #we collect problems here
    
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    if not any(char.isdigit() for char in password):
        errors.append("Password requires at least one digit in it")
    if not any(char.isupper() for char in password):
        errors.append("Password requires at least one Uppercase letter")
    if not any(char.islower() for char in password):
        errors.append("Password requires at least one lowercase letter")
    
    if errors:
        raise ValueError("\n".join(errors))
    
    return True
try:
    validate_password("@")
    print("Password is Valid!")
except IOError as e:
    print(f"Invalid:\n{e}")
    print(f"{type(e)}")