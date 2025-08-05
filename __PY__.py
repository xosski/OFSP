"""
Legacy entry point - redirects to main.py
This file is kept for compatibility but the main entry point is now main.py
"""

if __name__ == "__main__":
    print("Note: __PY__.py is deprecated. Please use main.py as the entry point.")
    
    # Import and run the main application
    try:
        from main import main
        main()
    except ImportError:
        print("Error: Could not import main.py")
        print("Please run: python main.py")
    except Exception as e:
        print(f"Error running application: {str(e)}")
        input("Press Enter to exit...")  # Keep console open
