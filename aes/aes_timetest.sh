echo "AES encryption..."

for file in ./../../../data_file_set/*; do 
    if [ -f "$file" ]; then 
        ./aescrypt -e -p 'password' "$file"
    fi 
    
done