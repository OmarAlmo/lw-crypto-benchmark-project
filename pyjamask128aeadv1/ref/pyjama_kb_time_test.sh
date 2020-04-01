echo "Pyjama encryption..."

# for file in ./../../../kb_data/*; do
#     if [ -f "$file" ]; then
#         ./pyjamask "$file"
#     fi
# done


./pyjamask  ./../../../kb_data/4kb.txt
./pyjamask  ./../../../kb_data/8kb.txt
./pyjamask  ./../../../kb_data/16kb.txt
./pyjamask  ./../../../kb_data/32kb.txt
./pyjamask  ./../../../kb_data/64kb.txt
./pyjamask  ./../../../kb_data/128kb.txt
./pyjamask  ./../../../kb_data/256kb.txt
./pyjamask  ./../../../kb_data/512kb.txt
./pyjamask  ./../../../kb_data/1mb.txt
./pyjamask  ./../../../kb_data/4mb.txt
./pyjamask  ./../../../kb_data/8mb.txt
./pyjamask  ./../../../kb_data/16mb.txt
./pyjamask  ./../../../kb_data/32mb.txt
./pyjamask  ./../../../kb_data/64mb.txt

echo "Done."
