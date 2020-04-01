echo "ACE encryption..."

for file in ./../../../../random_data_8MB/*; do 
    if [ -f "$file" ]; then 
        ./ace128 "$file"
    fi 
done

echo "Done."
