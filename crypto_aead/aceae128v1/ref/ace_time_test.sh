echo "ACE encryption..."

for file in ./../../../data_file_set/*; do 
    if [ -f "$file" ]; then 
        ./ace128 "$file"
    fi 
done

echo "Done."
