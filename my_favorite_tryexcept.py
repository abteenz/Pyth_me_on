def lets_divide(a, b):
    try:
        result = a / b
        return {
            'status': 0,
            'result': result,
            'error': None
        }
    except Exception as e:
        return {
            'status': -1,
            'result': None,
            'error': str(e)
        }

response = lets_divide(10, 2)
print(f"Status: {response['status']}")    # Status: 0
print(f"Result: {response['result']}")    # Result: 5.0

response = lets_divide(10, 0)
print(f"Error: {response['error']}")      # Error: division by zero