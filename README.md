Python 3.8+ was used to create the application files. Before running the files, ensure Python 3.8 or newer and the following libraries are installed:

| Library    | Task                        |
| Sklearn    | Machine Learning            |
| Numpy      | Mathematical Operations     |
| Pandas     | Data Analysis Tools         |
| Matplotlib | Graphics and Visualization  |
| Seaborn    | Advanced Visualization      |
| Joblib     | Model Serialization         |

The machine learning implementation phase consists of 3 main steps:
1. Data Pre-processing
2. Feature Importance Analysis
3. Machine Learning Training


### 1 - Data Pre-processing

**File:** `1_Data_Preprocessing.ipynb`
This notebook cleans, normalizes, and prepares raw network flow data for machine learning. Input CSV files should be placed in the `csv/` folder. The output is a processed CSV file used in subsequent steps.
### 2 - Feature Importance Analysis

**Files:**
- `2_a_Feature_Importance_Benign_Attack.ipynb`: Analyzes feature importance for distinguishing benign vs. attack traffic using statistical and ML methods.
- `2_b_Feature_Importance_Attacks_.ipynb`: Focuses on feature importance for different attack types, helping select relevant features for multi-class classification.
### 3 - Machine Learning Training

**Files:**
- `3_a_ML_Training_Benign_Attack.ipynb`: Trains and evaluates binary classifiers (benign vs. attack) using KNN, Random Forest, and XGBoost.
- `3_b_ML_Training_Attacks.ipynb`: Trains and evaluates multi-class classifiers for specific attack categories.
---

#### Running the NIDS
1. **Install Requirements**
    - Install Python 3.8+ and required libraries:
       ```bash
   pip install -r requirements.txt
   ```

2. **Prepare Data and Models**
   - Place pre-trained models in the `model/` directory as needed (download from kaggle here).

3. **Change directory to /src**

5. **Run the NIDS**
    - Start the GUI for real-time monitoring:
       ```bash
       sudo python3 -m nids.gui
   ```
---