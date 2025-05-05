# keyword_tracker.py
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import pandas as pd
import re
from collections import defaultdict, Counter

# === Simplified Keyword Categories ===
categories = [
    ("Bad Experience", ["worst", "terrible", "horrible", "awful", "disappointing", 
                      "bad service", "poor quality", "frustrating", "annoying", 
                      "never again", "waste of money", "scam"]),
    ("High Charges", ["too expensive", "high price", "overpriced", "hidden fees", 
                     "delivery charges", "platform fee"]),
    ("Customer Support", ["no support", "bad service", "unhelpful", "rude staff", 
                         "slow response", "ignored me", "no resolution"]),
    ("Quality Issues", ["broken", "not working", "poor quality", "defective", 
                      "missing parts", "wrong item", "damaged"]),
    ("Delivery Problems", ["late delivery", "never arrived", "wrong address", 
                         "missing order", "delayed", "slow shipping"]),
    ("App Issues", ["app crashes", "login problems", "bugs", "glitches", 
                   "freezes", "slow performance", "update broke it"]),
    ("Positive Feedback", ["great", "awesome", "amazing", "love it", "perfect", 
                         "excellent", "highly recommend", "best ever", "happy"]),
    ("Feature Request", ["should have", "would be nice", "please add", 
                        "missing feature", "wish it could"])
]

# General categories for unmatched keywords
GENERAL_CATEGORIES = [
    ("Positive", ["good", "nice", "great", "perfect", "happy"]),
    ("Negative", ["bad", "poor", "terrible", "awful", "disappointed"]),
    ("Technical", ["bug", "crash", "error", "freeze", "loading"]),
    ("Service", ["support", "help", "response", "rude", "professional"]),
    ("Other", [])
]

# Simplified Response Templates
RESPONSE_MAP = {
    "Positive Feedback": "Thank you for your kind words! We're thrilled you're enjoying our product.",
    "Bad Experience": "We're sorry to hear about your experience. Please contact support@example.com so we can make it right.",
    "High Charges": "We appreciate your feedback about pricing. Our team constantly reviews our pricing structure.",
    "Customer Support": "We apologize for the service experience. Our support team would like to follow up at support@example.com.",
    "Quality Issues": "We take quality seriously. Please email support@example.com with order details so we can investigate.",
    "Delivery Problems": "We're sorry about the delivery issues. Please share your order number at support@example.com.",
    "App Issues": "We're working to improve the app. Your report helps us identify issues to fix.",
    "Feature Request": "Thanks for the suggestion! We've shared it with our product team for consideration.",
    "No Keyword": ""
}

def clean_review_text(text):
    """Clean review text by removing patterns like 'X people found this helpful'"""
    if pd.isna(text):
        return text
    text = str(text)
    text = re.sub(r'\d+\s+people?\s+found\s+this\s+review\s+helpful', '', text, flags=re.IGNORECASE)
    return text.strip()

def should_include_keyword(keyword):
    """Filter keywords based on length and word count"""
    word_count = len(keyword.split())
    return (len(keyword) >= 3 or (1 <= word_count <= 3))

def extract_keywords(text):
    """Extract potential keywords from text"""
    if pd.isna(text) or not isinstance(text, str):
        return set()
    
    text = clean_review_text(text)
    words = re.findall(r'\b[\w\-]+\b', text.lower())
    keywords = set()
    
    # Single words
    for word in words:
        if len(word) >= 3:
            keywords.add(word)
    
    # Multi-word phrases
    for i in range(len(words) - 1):
        for j in range(2, 4):  # 2-3 word phrases
            if i + j <= len(words):
                phrase = ' '.join(words[i:i+j])
                if len(phrase.replace(' ', '')) >= 3:
                    keywords.add(phrase)
    
    return keywords

def categorize_keyword(keyword):
    """Categorize a keyword into general categories"""
    keyword_lower = keyword.lower()
    for category, terms in GENERAL_CATEGORIES:
        for term in terms:
            if term in keyword_lower:
                return category
    return "Other"

def categorize_review(text):
    text = clean_review_text(text)
    if pd.isna(text):
        return "No Keyword", {}, set()
    
    text_lower = text.lower()
    matched_keywords = defaultdict(list)
    all_keywords_in_review = extract_keywords(text_lower)
    unmatched_keywords = set(all_keywords_in_review)
    
    for label, keywords in categories:
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if (re.search(r'\b' + re.escape(keyword_lower) + r'\b', text_lower) and
                should_include_keyword(keyword)):
                matched_keywords[label].append(keyword)
                if keyword_lower in unmatched_keywords:
                    unmatched_keywords.remove(keyword_lower)
    
    if matched_keywords:
        primary_category = next(iter(matched_keywords))
        return primary_category, matched_keywords, unmatched_keywords
    return "No Keyword", {}, unmatched_keywords

class KeywordTracker:
    def __init__(self, root):
        self.root = root
        self.root.title("Keyword Tracker")
        self.root.geometry("800x600")
        self.setup_ui()
    
    def setup_ui(self):
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        input_label = tk.Label(main_frame, text="Paste Reviews Below:", 
                             font=("Arial", 12, "bold"))
        input_label.pack(pady=(0, 10))
        
        self.text_input = scrolledtext.ScrolledText(
            main_frame, 
            wrap=tk.WORD, 
            width=90, 
            height=20,
            font=("Arial", 10)
        )
        self.text_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=15)
        
        process_btn = tk.Button(
            button_frame, 
            text="Analyze Reviews", 
            command=self.process_reviews,
            font=("Arial", 12), 
            bg="#4CAF50", 
            fg="white",
            padx=10,
            pady=5
        )
        process_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(
            button_frame, 
            text="Clear", 
            command=self.clear_input,
            font=("Arial", 12), 
            bg="#f44336", 
            fg="white",
            padx=10,
            pady=5
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
    
    def clear_input(self):
        self.text_input.delete("1.0", tk.END)
    
    def process_reviews(self):
        try:
            raw_reviews = self.text_input.get("1.0", tk.END).strip()
            if not raw_reviews:
                messagebox.showwarning("No Input", "Please paste reviews to analyze.")
                return

            lines = [line.strip() for line in raw_reviews.splitlines() if line.strip()]
            if len(lines) < 3:
                messagebox.showwarning("Insufficient Data", "Please provide complete reviews.")
                return

            parsed_data = []
            all_keywords = defaultdict(set)
            all_unmatched_keywords = defaultdict(set)
            
            matched_keyword_counter = Counter()
            unmatched_keyword_counter = Counter()
            
            i = 0
            total_lines = len(lines)

            while i < total_lines:
                if (i + 1 < total_lines and 
                    re.match(r'^.{2,100}$', lines[i], re.UNICODE) and 
                    re.match(r'^[A-Za-z]+ \d{1,2}, \d{4}$', lines[i+1])):

                    name = lines[i]
                    date = lines[i+1]
                    review_lines = []
                    i += 2

                    while i < total_lines:
                        if "Did you find this helpful" in lines[i]:
                            i += 1
                            continue
                        if (i + 1 < total_lines and lines[i].lower() == "company" and 
                            re.match(r'^[A-Za-z]+ \d{1,2}, \d{4}$', lines[i+1])):
                            break
                        if (re.match(r'^.{2,100}$', lines[i], re.UNICODE) and 
                            i + 1 < total_lines and 
                            re.match(r'^[A-Za-z]+ \d{1,2}, \d{4}$', lines[i+1])):
                            break
                        review_lines.append(lines[i])
                        i += 1

                    review = ' '.join(review_lines).strip()
                    review = clean_review_text(review)

                    category, matched_keywords, review_unmatched = categorize_review(review)
                    
                    for keyword in review_unmatched:
                        general_category = categorize_keyword(keyword)
                        all_unmatched_keywords[general_category].add(keyword)
                        unmatched_keyword_counter[keyword] += 1
                    
                    formatted_keywords = ""
                    if matched_keywords:
                        for cat, keywords in matched_keywords.items():
                            formatted_keywords += f"{cat}: " + ", ".join(f'"{kw}"' for kw in keywords) + "\n"
                            for kw in keywords:
                                matched_keyword_counter[kw] += 1
                        formatted_keywords = formatted_keywords.strip()
                    
                    for cat, keywords in matched_keywords.items():
                        for kw in keywords:
                            if should_include_keyword(kw):
                                all_keywords[cat].add(kw)

                    response = ""
                    if i + 1 < total_lines and lines[i].lower() == "company":
                        i += 2
                        response_lines = []
                        while i < total_lines:
                            if (re.match(r'^.{2,100}$', lines[i], re.UNICODE) and 
                                i + 1 < total_lines and 
                                re.match(r'^[A-Za-z]+ \d{1,2}, \d{4}$', lines[i+1])) or lines[i].lower() == "company":
                                break
                            response_lines.append(lines[i])
                            i += 1
                        response = ' '.join(response_lines).strip()

                    parsed_data.append([name, date, review, response, category, formatted_keywords])
                else:
                    i += 1

            if not parsed_data:
                messagebox.showinfo("No Reviews", "No valid reviews found in the input.")
                return

            df = pd.DataFrame(parsed_data, columns=[
                "Customer Name", 
                "Date", 
                "Review", 
                "Company Response", 
                "Category", 
                "Matched Keywords"
            ])
            
            df["Suggested Response"] = df["Category"].map(RESPONSE_MAP)
            df["Missed Response"] = (df["Category"] != "No Keyword") & (df["Company Response"].str.strip() == "")
            df["Incorrect Response"] = (df["Category"] != "Positive Feedback") & (
                df["Company Response"].str.contains("thank you", case=False)
            )

            keyword_data = []
            seen_keywords = set()
            
            for category in sorted(all_keywords.keys()):
                category_keywords = []
                for keyword in sorted(all_keywords[category]):
                    kw_lower = keyword.lower()
                    if kw_lower not in seen_keywords:
                        category_keywords.append(f'"{keyword}"')
                        seen_keywords.add(kw_lower)
                
                if category_keywords:
                    keyword_data.append([
                        category, 
                        ", ".join(category_keywords)
                    ])

            keyword_df = pd.DataFrame(keyword_data, columns=["Category", "Found Keywords"])

            unmatched_data = []
            seen_unmatched = set()
            
            for category in sorted(all_unmatched_keywords.keys()):
                if not all_unmatched_keywords[category]:
                    continue
                    
                category_keywords = []
                for keyword in sorted(all_unmatched_keywords[category]):
                    kw_lower = keyword.lower()
                    if kw_lower not in seen_unmatched:
                        category_keywords.append(f'"{keyword}"')
                        seen_unmatched.add(kw_lower)
                
                if category_keywords:
                    unmatched_data.append([
                        category,
                        ", ".join(category_keywords)
                    ])

            unmatched_df = pd.DataFrame(unmatched_data, columns=["Category", "Keywords"])

            matched_freq_df = pd.DataFrame(matched_keyword_counter.most_common(), 
                                         columns=["Keyword", "Frequency"])
            unmatched_freq_df = pd.DataFrame(unmatched_keyword_counter.most_common(), 
                                           columns=["Keyword", "Frequency"])

            output_file = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
                title="Save Analysis Report",
                initialfile="Review_Analysis.xlsx"
            )
            
            if not output_file:
                return
            
            try:
                with pd.ExcelWriter(output_file) as writer:
                    df.to_excel(writer, sheet_name='Review Analysis', index=False)
                    keyword_df.to_excel(writer, sheet_name='Found Keywords', index=False)
                    unmatched_df.to_excel(writer, sheet_name='Unmatched Keywords', index=False)
                    matched_freq_df.to_excel(writer, sheet_name='Matched Keyword Freq', index=False)
                    unmatched_freq_df.to_excel(writer, sheet_name='Unmatched Keyword Freq', index=False)
                
                messagebox.showinfo(
                    "Success",
                    f"Analyzed {len(parsed_data)} reviews.\n"
                    f"Found {len(keyword_df)} categories with keywords.\n"
                    f"Report saved to:\n{output_file}"
                )
            except Exception as e:
                messagebox.showerror(
                    "Save Error",
                    f"Failed to save file:\n{str(e)}\n\n"
                    "Please ensure the file is not open in another program."
                )

        except Exception as e:
            messagebox.showerror(
                "Error",
                f"An error occurred:\n{str(e)}\n\n"
                "Please check your input and try again."
            )

if __name__ == "__main__":
    root = tk.Tk()
    app = KeywordTracker(root)
    root.mainloop()