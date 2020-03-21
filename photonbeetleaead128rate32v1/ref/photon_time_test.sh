echo "Photon encryption..."

# for file in ./../../../data_file_set/*; do 
for file in /Users/omaralmo/Desktop/courses/CSI4900/data_file_set/*; do 
    if [ -f "$file" ]; then 
        ./photon "$file"
    fi 
done

echo "Done."
