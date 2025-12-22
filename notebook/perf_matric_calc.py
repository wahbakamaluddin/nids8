while True:
    try:
        print("Enter confusion matrix values:")
        TN = float(input("Enter TN: "))
        TP = float(input("Enter TP: "))
        FN = float(input("Enter FN: "))
        FP = float(input("Enter FP: "))

        print(f"""
        accuracy = {(TN + TP) / (FP + FN + TP + TN)}
        precision = {TP / (TP + FP)}
        recall = {TP / (TP + FN)}
        f1_score = {2 * ( (TP / (TP + FP)) * (TP / (TP + FN)) ) / ( (TP / (TP + FP)) + (TP / (TP + FN)) )}
        """)
    
    except ValueError:
        print("Invalid input. Please enter numeric values.")

