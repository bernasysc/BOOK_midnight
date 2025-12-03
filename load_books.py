import pandas as pd
from app import app, db, Book

# ----------------------------
# 1️⃣ Configuration
# ----------------------------
PLACEHOLDER_IMAGE = "/static/no_image.png"

# ----------------------------
# 2️⃣ Load and clean dataset
# ----------------------------

# Load Kaggle dataset
df_main = pd.read_csv("data/data.csv")

# Fill missing image URLs with placeholder
df_main['image_url'] = df_main['thumbnail'].fillna(PLACEHOLDER_IMAGE)

# Fill missing values for other fields
df_main['description'] = df_main['description'].fillna("")
df_main['category'] = df_main['categories'].fillna("Unknown")
df_main['publisher'] = df_main.get('publisher', "Unknown")  # Some Kaggle datasets might not have this
df_main['publish_date'] = df_main.get('published_year', "")
df_main['price'] = df_main.get('price', "Unknown")

# Load best-selling books dataset
df_bestsellers = pd.read_csv("data/best-selling-books.csv")

print(f"📘 Total books to load: {len(df_main)}")
print(f"🏆 Best-selling books: {len(df_bestsellers)}")

# ----------------------------
# 3️⃣ Create database and load books
# ----------------------------
with app.app_context():
    db.drop_all()
    db.create_all()

    total = len(df_main)
    print(f"📚 Loading {total} books into the database...")

    # Load main books
    for i, (_, row) in enumerate(df_main.iterrows(), start=1):
        # Get ratings
        avg_rating = row.get("average_rating", None)
        try:
            avg_rating = float(avg_rating) if avg_rating else None
        except (ValueError, TypeError):
            avg_rating = None
        
        ratings_count = row.get("ratings_count", None)
        try:
            ratings_count = int(ratings_count) if ratings_count else None
        except (ValueError, TypeError):
            ratings_count = None
        
        num_pages = row.get("num_pages", None)
        try:
            num_pages = int(num_pages) if num_pages else None
        except (ValueError, TypeError):
            num_pages = None
        
        book = Book(
            title=row.get("title", ""),
            authors=row.get("authors", ""),
            description=row.get("description", ""),
            category=row.get("category", "Unknown"),
            publisher=row.get("publisher", "Unknown"),
            publish_date=str(row.get("publish_date", "")),
            price=str(row.get("price", "Unknown")),
            image_url=row.get("image_url", PLACEHOLDER_IMAGE),
            is_bestseller=False,
            average_rating=avg_rating,
            num_pages=num_pages,
            ratings_count=ratings_count
        )
        db.session.add(book)

        if i % 1000 == 0:
            print(f"✔ Loaded {i}/{total} books...")

    db.session.commit()
    print(f"✔ Loaded {total} books from main dataset")

    # Load best-selling books (add as new books if not exists)
    print("\n🏆 Loading best-selling books...")
    bestsellers_added = 0
    for i, (_, row) in enumerate(df_bestsellers.iterrows(), start=1):
        # Check if book already exists by title
        existing = Book.query.filter_by(title=row.get("Book", "")).first()
        
        # Get sales in millions
        sales = row.get("Approximate sales in millions", 0)
        try:
            sales = int(sales)
        except (ValueError, TypeError):
            sales = 0
        
        if existing:
            # Mark as bestseller and update sales
            existing.is_bestseller = True
            existing.sales_millions = sales
        else:
            # Add as new book
            bestseller = Book(
                title=row.get("Book", ""),
                authors=row.get("Author(s)", ""),
                description="",
                category=row.get("Genre", "Unknown"),
                publisher="Unknown",
                publish_date=str(row.get("First published", "")),
                price="Unknown",
                image_url=PLACEHOLDER_IMAGE,
                is_bestseller=True,
                sales_millions=sales
            )
            db.session.add(bestseller)
            bestsellers_added += 1

    db.session.commit()
    print(f"✔ Processed {len(df_bestsellers)} best-selling books ({bestsellers_added} new)")
    print("🎉 All books loaded successfully!")
