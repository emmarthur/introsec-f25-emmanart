
# Read words from rockyou20.txt
with open('rockyou20.txt', 'r') as f:
    rock20words = [line.strip() for line in f]

# Generate combinations
def generate_combinations(wordlist, n):
    combinations = []
    def dfs(index, trip):
        if index == n:
            combinations.append(trip.copy())
            return
        for i in range(len(wordlist)):
            trip.append(wordlist[i])
            dfs(index + 1, trip.copy())
            trip.pop()
    dfs(0, [])
    return [" ".join(combo) for combo in combinations]

generated_combinations = generate_combinations(rock20words, 3)

# Write combinations to a file
with open('three_word_combinations.txt', 'w') as f:
    for combination in generated_combinations:
        f.write(combination + '\n')
