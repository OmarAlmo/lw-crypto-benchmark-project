echo "ACE encryption..."

for file in /Users/omaralmo/Desktop/courses/CSI4900/kb_data/*; do 
    if [ -f "$file" ]; then 
        ./aes128 "$file"
    fi 
done

echo "Done."
