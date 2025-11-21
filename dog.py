def process_user(user_id):
    # Validation with early returns
    if user_id is None:
        print("Error: No user ID")
        return None  # Exit immediately
    
    if user_id < 0:
        print("Error: Invalid user ID")
        return None  # Exit immediately
    
    # Main logic only runs if validations passed
    user = database.get(user_id)
    
    if not user:
        print("Error: User not found")
        return None  # Exit immediately
    
    # Process user
    return user.process()

process_user(11)