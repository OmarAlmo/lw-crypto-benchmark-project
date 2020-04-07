echo "Photon encryption..."


i=2
while [ $i -le 500000 ]
do
  echo $i
  ./photon $i
  ((i=i*2))
done


echo "Done."
