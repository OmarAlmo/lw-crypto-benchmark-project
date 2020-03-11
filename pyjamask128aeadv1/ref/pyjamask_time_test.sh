echo "Pyjamask encryption..."

for file in ./../../../data_file_set/*; do 
    if [ -f "$file" ]; then 
        ./pyjamask "$file"
    fi 
done

echo "Done."
